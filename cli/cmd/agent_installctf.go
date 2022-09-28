//
// Author:: Nicholas Schmeller (<nick.schmeller@lacework.net>)
// Copyright:: Copyright 2022, Lacework Inc.
// License:: Apache License, Version 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package cmd

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/lacework/go-sdk/lwrunner"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func awsCaptureTheFlagSSH(_ *cobra.Command, args []string) error {
	runners, err := awsFindRunnersToCapture()
	if err != nil {
		return err
	}

	for _, runner := range runners {
		cli.Log.Debugw("runner: ", "runner", runner)
		cli.Log.Debugw("runner user: ", "user", runner.Runner.User)
		cli.Log.Debugw("runner region: ", "region", runner.Region)
		cli.Log.Debugw("runner az: ", "az", runner.AvailabilityZone)
		cli.Log.Debugw("runner instance ID: ", "instance ID", runner.InstanceID)
		cli.Log.Debugw("runner: ", "runner hostname", runner.Runner.Hostname)

		err := runner.Runner.UseIdentityFile(agentCmdState.InstallIdentityFile)
		if err != nil {
			return errors.Wrap(err, "unable to use provided identity file")
		}

		if err := verifyAccessToRemoteHost(&runner.Runner); err != nil {
			cli.Log.Debugw("verifyAccessToRemoteHost failed")
			return err
		}

		if err := isAgentInstalledOnRemoteHost(&runner.Runner); err != nil {
			cli.Log.Debugw("isAgentInstalledOnRemoteHost failed")
			return err
		}

		token := agentCmdState.InstallAgentToken
		if token == "" {
			// user didn't provide an agent token
			cli.Log.Debugw("agent token not provided")
			var err error
			token, err = selectAgentAccessToken()
			if err != nil {
				return err
			}
		}
		cmd := fmt.Sprintf("sudo sh -c \"curl -sSL %s | sh -s -- %s\"", agentInstallDownloadURL, token)
		err = runInstallCommandOnRemoteHost(&runner.Runner, cmd)
		if err != nil {
			cli.Log.Debugw("runInstallCommandOnRemoteHost failed")
			return err
		}
	}

	return nil
}

func awsCaptureTheFlagEC2IC(_ *cobra.Command, args []string) error {
	runners, err := awsFindRunnersToCapture()
	if err != nil {
		return err
	}

	for _, runner := range runners {
		cli.Log.Debugw("runner: ", "runner", runner)
		cli.Log.Debugw("runner user: ", "user", runner.Runner.User)
		cli.Log.Debugw("runner region: ", "region", runner.Region)
		cli.Log.Debugw("runner az: ", "az", runner.AvailabilityZone)
		cli.Log.Debugw("runner instance ID: ", "instance ID", runner.InstanceID)
		cli.Log.Debugw("runner: ", "runner hostname", runner.Runner.Hostname)
		err := runner.SendAndUseIdentityFile()
		if err != nil {
			return errors.Wrap(err, "unable to use provided identity file")
		}

		if err := verifyAccessToRemoteHost(&runner.Runner); err != nil {
			cli.Log.Debugw("verifyAccessToRemoteHost failed")
			return err
		}

		if err := isAgentInstalledOnRemoteHost(&runner.Runner); err != nil {
			cli.Log.Debugw("isAgentInstalledOnRemoteHost failed")
			return err
		}

		token := agentCmdState.InstallAgentToken
		if token == "" {
			// user didn't provide an agent token
			cli.Log.Debugw("agent token not provided")
			var err error
			token, err = selectAgentAccessToken()
			if err != nil {
				return err
			}
		}
		cmd := fmt.Sprintf("sudo sh -c \"curl -sSL %s | sh -s -- %s\"", agentInstallDownloadURL, token)
		err = runInstallCommandOnRemoteHost(&runner.Runner, cmd)
		if err != nil {
			cli.Log.Debugw("runInstallCommandOnRemoteHost failed")
			return err
		}
	}

	return nil
}

func awsFindRunnersToCapture() ([]*lwrunner.AWSRunner, error) {
	regions, err := awsFindRegions()
	if err != nil {
		return nil, err
	}

	allRunners := []*lwrunner.AWSRunner{}
	for _, region := range regions {
		regionRunners, err := awsFindRunnersInRegion(*region.RegionName)
		if err != nil {
			return nil, err
		}
		allRunners = append(allRunners, regionRunners...)
	}

	return allRunners, nil
}

// awsFindRegions queries the AWS API to list all the regions that
// are enabled for the user's AWS account. Use the "include_regions"
// command-line flag to only get regions in this list.
func awsFindRegions() ([]types.Region, error) {
	// Describe all regions that are enabled for the account
	var filters []types.Filter
	if len(agentCmdState.CTFIncludeRegions) > 0 {
		filters = []types.Filter{
			{
				Name:   aws.String("region-name"),
				Values: agentCmdState.CTFIncludeRegions,
			},
		}
	}
	input := &ec2.DescribeRegionsInput{
		Filters: filters,
	}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	svc := ec2.New(ec2.Options{
		Credentials: cfg.Credentials,
		Region:      "us-west-2", // use us-west-2 for lack of a better region
	})

	output, err := svc.DescribeRegions(context.TODO(), input)
	if err != nil {
		return nil, err
	}
	return output.Regions, nil
}

func awsFindRunnersInRegion(region string) ([]*lwrunner.AWSRunner, error) {
	var (
		tagKey = agentCmdState.CTFInfraTagKey
		user   = "ubuntu"
	)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	svc := ec2.New(ec2.Options{
		Credentials: cfg.Credentials,
		Region:      region,
	})

	var filter []types.Filter
	if tagKey != "" {
		filter = []types.Filter{
			{
				Name: aws.String("tag-key"),
				Values: []string{
					tagKey,
				},
			},
		}
	}
	input := &ec2.DescribeInstancesInput{
		Filters: filter,
	}

	result, err := svc.DescribeInstances(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	runners := []*lwrunner.AWSRunner{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if instance.PublicIpAddress != nil {
				runner := lwrunner.NewAWSRunner(user, *instance.PublicIpAddress, region, *instance.Placement.AvailabilityZone, *instance.InstanceId, verifyHostCallback)
				runners = append(runners, runner)
			}
		}
	}

	return runners, nil
}
