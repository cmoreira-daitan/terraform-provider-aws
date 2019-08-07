package aws

import (
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/elb"
)

// Determine if a particular policy is assigned to an ELB listener
func resourceAwsELBSticknessPolicyAssigned(policyName, lbName, lbPort string, elbconn *elb.ELB) (bool, error) {
	describeElbOpts := &elb.DescribeLoadBalancersInput{
		LoadBalancerNames: []*string{aws.String(lbName)},
	}
	describeResp, err := elbconn.DescribeLoadBalancers(describeElbOpts)
	if err != nil {
		if ec2err, ok := err.(awserr.Error); ok {
			if ec2err.Code() == "LoadBalancerNotFound" {
				return false, nil
			}
		}
		return false, fmt.Errorf("Error retrieving ELB description: %s", err)
	}

	if len(describeResp.LoadBalancerDescriptions) != 1 {
		return false, fmt.Errorf("Unable to find ELB: %#v", describeResp.LoadBalancerDescriptions)
	}

	lb := describeResp.LoadBalancerDescriptions[0]
	assigned := false
	for _, listener := range lb.ListenerDescriptions {
		if lbPort != strconv.Itoa(int(*listener.Listener.LoadBalancerPort)) {
			continue
		}

		for _, name := range listener.PolicyNames {
			if policyName == *name {
				assigned = true
				break
			}
		}
	}

	return assigned, nil
}
