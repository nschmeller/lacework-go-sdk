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

func awsCaptureTheFlag(_ *cobra.Command, args []string) error {
	runners, err := awsFindRunnersToCapture()
	if err != nil {
		return err
	}

	for _, runner := range runners {
		cli.Log.Debugw("runner: ", "runner", runner)
		cli.Log.Debugw("ssh ctf settings", "identity_file", agentCmdState.InstallIdentityFile)
		err := runner.UseIdentityFile(agentCmdState.InstallIdentityFile)
		if err != nil {
			return errors.Wrap(err, "unable to use provided identity file")
		}

		if err := verifyAccessToRemoteHost(runner); err != nil {
			cli.Log.Debugw("verifyAccessToRemoteHost failed")
			return err
		}

		if err := isAgentInstalledOnRemoteHost(runner); err != nil {
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
		err = runInstallCommandOnRemoteHost(runner, cmd)
		if err != nil {
			cli.Log.Debugw("runInstallCommandOnRemoteHost failed")
			return err
		}
	}

	return nil
}

func awsFindRunnersToCapture() ([]*lwrunner.Runner, error) {
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
		Region:      "us-east-2",
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

	runners := []*lwrunner.Runner{}

	result, err := svc.DescribeInstances(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if instance.PublicIpAddress != nil {
				runner := lwrunner.New(user, *instance.PublicIpAddress, verifyHostCallback)
				runners = append(runners, runner)
			}
		}
	}

	return runners, nil
}
