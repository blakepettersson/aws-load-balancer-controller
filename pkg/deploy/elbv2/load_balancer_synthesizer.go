package elbv2

import (
	"context"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/deploy/ec2"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/networking"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	elbv2sdk "github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/aws/services"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/deploy/tracking"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/model/core"
	ec2model "sigs.k8s.io/aws-load-balancer-controller/pkg/model/ec2"
	elbv2model "sigs.k8s.io/aws-load-balancer-controller/pkg/model/elbv2"
)

const (
	lbAttrsDeletionProtectionEnabled = "deletion_protection.enabled"
)

// NewLoadBalancerSynthesizer constructs loadBalancerSynthesizer
func NewLoadBalancerSynthesizer(elbv2Client services.ELBV2, trackingProvider tracking.Provider, taggingManager TaggingManager, ec2TaggingManager ec2.TaggingManager,
	sgManager ec2.SecurityGroupManager, lbManager LoadBalancerManager, logger logr.Logger, stack core.Stack) *loadBalancerSynthesizer {
	return &loadBalancerSynthesizer{
		elbv2Client:       elbv2Client,
		trackingProvider:  trackingProvider,
		taggingManager:    taggingManager,
		ec2TaggingManager: ec2TaggingManager,
		sgManager:         sgManager,
		lbManager:         lbManager,
		logger:            logger,
		stack:             stack,
	}
}

// loadBalancerSynthesizer is responsible for synthesize LoadBalancer resources types for certain stack.
type loadBalancerSynthesizer struct {
	elbv2Client       services.ELBV2
	trackingProvider  tracking.Provider
	taggingManager    TaggingManager
	sgManager         ec2.SecurityGroupManager
	ec2TaggingManager ec2.TaggingManager
	lbManager         LoadBalancerManager
	logger            logr.Logger

	stack core.Stack
}

func (s *loadBalancerSynthesizer) Synthesize(ctx context.Context) error {
	var resLBs []*elbv2model.LoadBalancer
	s.stack.ListResources(&resLBs)
	sdkLBs, err := s.findSDKLoadBalancers(ctx)
	if err != nil {
		return err
	}

	matchedResAndSDKLBs, unmatchedResLBs, unmatchedSDKLBs, err := matchResAndSDKLoadBalancers(resLBs, sdkLBs, s.trackingProvider.ResourceIDTagKey())
	if err != nil {
		return err
	}

	// For LoadBalancers, we delete unmatched ones first given below facts:
	//  * LoadBalancer delete will automatically delete listeners attached to it.
	//  * we can avoid the operation to detach a targetGroup from unmatched LBs. (a targetGroup can only attach to one LB).
	// I don't like this, but it's the easiest solution to meet our requirement :D.
	for _, sdkLB := range unmatchedSDKLBs {
		if err := s.lbManager.Delete(ctx, sdkLB); err != nil {
			errMessage := err.Error()
			if strings.Contains(errMessage, "OperationNotPermitted") && strings.Contains(errMessage, "deletion protection") {
				s.disableDeletionProtection(sdkLB.LoadBalancer)
				if err = s.lbManager.Delete(ctx, sdkLB); err != nil {
					return err
				}

				return nil
			}

			// The LB can't be deleted; let's try to instead update the security groups
			err = s.resetLBSecurityGroups(ctx, sdkLB)
			if err != nil {
				return err
			}
		}
	}
	for _, resLB := range unmatchedResLBs {
		lbStatus, err := s.lbManager.Create(ctx, resLB)
		if err != nil {
			return err
		}
		resLB.SetStatus(lbStatus)
	}
	for _, resAndSDKLB := range matchedResAndSDKLBs {
		lbStatus, err := s.lbManager.Update(ctx, resAndSDKLB.resLB, resAndSDKLB.sdkLB)
		if err != nil {
			return err
		}
		resAndSDKLB.resLB.SetStatus(lbStatus)
	}
	return nil
}

func (s *loadBalancerSynthesizer) resetLBSecurityGroups(ctx context.Context, sdkLB LoadBalancerWithTags) error {
	lb := newLoadBalancerFromSDKLoadBalancer(s.stack, "LoadBalancer", sdkLB)

	if len(lb.Spec.SecurityGroups) > 0 {
		sg, err := s.findSDKSecurityGroup(ctx)
		if err != nil {
			return err
		}

		s.logger.Info("Security group", "sg", sg)

		var sgId core.StringToken

		if sg != nil {
			sgId = core.LiteralStringToken(sg.SecurityGroupID)
		} else {
			ec2SG, err := s.sgManager.Create(ctx, ec2model.NewSecurityGroup(s.stack, "ManagedLBSecurityGroup", ec2model.SecurityGroupSpec{
				GroupName:   "something",
				Description: "A dummy SG",
				Tags:        map[string]string{"empty": "true"},
			}))
			if err != nil {
				return err
			}
			sgId = core.LiteralStringToken(ec2SG.GroupID)
		}

		lb.Spec.SecurityGroups = []core.StringToken{sgId}

		lbStatus, err := s.lbManager.Update(ctx, lb, sdkLB)
		if err != nil {
			return err
		}

		lb.SetStatus(lbStatus)
	}

	return nil
}

func newLoadBalancerFromSDKLoadBalancer(stack core.Stack, id string, sdkLB LoadBalancerWithTags) *elbv2model.LoadBalancer {
	lb := sdkLB.LoadBalancer
	scheme := elbv2model.LoadBalancerScheme(*lb.Scheme)
	addressType := elbv2model.IPAddressType(*lb.IpAddressType)
	balancerType := elbv2model.LoadBalancerType(*lb.Type)
	var sgs []core.StringToken

	var mappings []elbv2model.SubnetMapping
	for _, zone := range lb.AvailabilityZones {
		if len(zone.LoadBalancerAddresses) > 0 {
			for _, address := range zone.LoadBalancerAddresses {
				mappings = append(mappings, elbv2model.SubnetMapping{
					AllocationID:       address.AllocationId,
					PrivateIPv4Address: address.PrivateIPv4Address,
					SubnetID:           *zone.SubnetId,
				})
			}
		} else {
			mappings = append(mappings, elbv2model.SubnetMapping{
				SubnetID: *zone.SubnetId,
			})
		}
	}

	for _, group := range lb.SecurityGroups {
		sgs = append(sgs, core.LiteralStringToken(*group))
	}

	return elbv2model.NewLoadBalancer(stack, id,
		elbv2model.LoadBalancerSpec{
			Name:                  *lb.LoadBalancerName,
			Type:                  balancerType,
			Scheme:                &scheme,
			Tags:                  sdkLB.Tags,
			IPAddressType:         &addressType,
			CustomerOwnedIPv4Pool: lb.CustomerOwnedIpv4Pool,
			SecurityGroups:        sgs,
			SubnetMappings:        mappings,
		})
}

func (s *loadBalancerSynthesizer) disableDeletionProtection(lb *elbv2sdk.LoadBalancer) error {
	input := &elbv2sdk.ModifyLoadBalancerAttributesInput{
		Attributes: []*elbv2sdk.LoadBalancerAttribute{
			{
				Key:   awssdk.String(lbAttrsDeletionProtectionEnabled),
				Value: awssdk.String("false"),
			},
		},
		LoadBalancerArn: lb.LoadBalancerArn,
	}
	_, err := s.elbv2Client.ModifyLoadBalancerAttributes(input)
	return err
}

func (s *loadBalancerSynthesizer) PostSynthesize(ctx context.Context) error {
	// nothing to do here.
	return nil
}

// findSDKSecurityGroups will find all AWS SecurityGroups created for stack.
func (s *loadBalancerSynthesizer) findSDKSecurityGroup(ctx context.Context) (*networking.SecurityGroupInfo, error) {
	stackTags := s.trackingProvider.StackTags(s.stack)
	stackTagsLegacy := s.trackingProvider.StackTagsLegacy(s.stack)

	groups, err := s.ec2TaggingManager.ListSecurityGroups(ctx,
		tracking.TagsAsTagFilter(appendEmptyTag(stackTags)),
		tracking.TagsAsTagFilter(appendEmptyTag(stackTagsLegacy)),
	)

	if err != nil {
		return nil, err
	}

	if len(groups) > 0 {
		return &groups[0], nil
	}

	return nil, nil
}

func appendEmptyTag(tmp map[string]string) map[string]string {
	stackTags := make(map[string]string, len(tmp)+1)
	for k, v := range tmp {
		stackTags[k] = v
	}
	stackTags["empty"] = "true"
	return stackTags
}

// findSDKLoadBalancers will find all AWS LoadBalancer created for stack.
func (s *loadBalancerSynthesizer) findSDKLoadBalancers(ctx context.Context) ([]LoadBalancerWithTags, error) {
	stackTags := s.trackingProvider.StackTags(s.stack)
	stackTagsLegacy := s.trackingProvider.StackTagsLegacy(s.stack)
	return s.taggingManager.ListLoadBalancers(ctx,
		tracking.TagsAsTagFilter(stackTags),
		tracking.TagsAsTagFilter(stackTagsLegacy))
}

type resAndSDKLoadBalancerPair struct {
	resLB *elbv2model.LoadBalancer
	sdkLB LoadBalancerWithTags
}

func matchResAndSDKLoadBalancers(resLBs []*elbv2model.LoadBalancer, sdkLBs []LoadBalancerWithTags,
	resourceIDTagKey string) ([]resAndSDKLoadBalancerPair, []*elbv2model.LoadBalancer, []LoadBalancerWithTags, error) {
	var matchedResAndSDKLBs []resAndSDKLoadBalancerPair
	var unmatchedResLBs []*elbv2model.LoadBalancer
	var unmatchedSDKLBs []LoadBalancerWithTags

	resLBsByID := mapResLoadBalancerByResourceID(resLBs)
	sdkLBsByID, err := mapSDKLoadBalancerByResourceID(sdkLBs, resourceIDTagKey)
	if err != nil {
		return nil, nil, nil, err
	}

	resLBIDs := sets.StringKeySet(resLBsByID)
	sdkLBIDs := sets.StringKeySet(sdkLBsByID)
	for _, resID := range resLBIDs.Intersection(sdkLBIDs).List() {
		resLB := resLBsByID[resID]
		sdkLBs := sdkLBsByID[resID]
		foundMatch := false
		for _, sdkLB := range sdkLBs {
			if isSDKLoadBalancerRequiresReplacement(sdkLB, resLB) {
				unmatchedSDKLBs = append(unmatchedSDKLBs, sdkLB)
				continue
			}
			matchedResAndSDKLBs = append(matchedResAndSDKLBs, resAndSDKLoadBalancerPair{
				resLB: resLB,
				sdkLB: sdkLB,
			})
			foundMatch = true
		}
		if !foundMatch {
			unmatchedResLBs = append(unmatchedResLBs, resLB)
		}
	}
	for _, resID := range resLBIDs.Difference(sdkLBIDs).List() {
		unmatchedResLBs = append(unmatchedResLBs, resLBsByID[resID])
	}
	for _, resID := range sdkLBIDs.Difference(resLBIDs).List() {
		unmatchedSDKLBs = append(unmatchedSDKLBs, sdkLBsByID[resID]...)
	}

	return matchedResAndSDKLBs, unmatchedResLBs, unmatchedSDKLBs, nil
}

func mapResLoadBalancerByResourceID(resLBs []*elbv2model.LoadBalancer) map[string]*elbv2model.LoadBalancer {
	resLBsByID := make(map[string]*elbv2model.LoadBalancer, len(resLBs))
	for _, resLB := range resLBs {
		resLBsByID[resLB.ID()] = resLB
	}
	return resLBsByID
}

func mapSDKLoadBalancerByResourceID(sdkLBs []LoadBalancerWithTags, resourceIDTagKey string) (map[string][]LoadBalancerWithTags, error) {
	sdkLBsByID := make(map[string][]LoadBalancerWithTags, len(sdkLBs))
	for _, sdkLB := range sdkLBs {
		resourceID, ok := sdkLB.Tags[resourceIDTagKey]
		if !ok {
			return nil, errors.Errorf("unexpected loadBalancer with no resourceID: %v", awssdk.StringValue(sdkLB.LoadBalancer.LoadBalancerArn))
		}
		sdkLBsByID[resourceID] = append(sdkLBsByID[resourceID], sdkLB)
	}
	return sdkLBsByID, nil
}

// isSDKLoadBalancerRequiresReplacement checks whether a sdk LoadBalancer requires replacement to fulfill a LoadBalancer resource.
func isSDKLoadBalancerRequiresReplacement(sdkLB LoadBalancerWithTags, resLB *elbv2model.LoadBalancer) bool {
	if string(resLB.Spec.Type) != awssdk.StringValue(sdkLB.LoadBalancer.Type) {
		return true
	}
	if resLB.Spec.Scheme != nil && string(*resLB.Spec.Scheme) != awssdk.StringValue(sdkLB.LoadBalancer.Scheme) {
		return true
	}
	return false
}
