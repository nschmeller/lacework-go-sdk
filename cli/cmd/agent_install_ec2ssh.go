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
	"fmt"
	"sync"

	"github.com/lacework/go-sdk/lwrunner"
	"github.com/spf13/cobra"
)

var (
	agentInstallAWSSSHCmd = &cobra.Command{
		Use:   "ec2-ssh",
		Args:  cobra.NoArgs,
		Short: "Use SSH to securely connect to EC2 instances",
		Long: `This command installs the agent on all EC2 instances in an AWS account
using SSH.

To filter by one or more regions:

    lacework agent install ec2-ssh --include_regions us-west-2,us-east-2

To filter by instance tag:

    lacework agent install ec2-ssh --tag TagName,TagValue

To filter by instance tag key:

    lacework agent install ec2-ssh --tag_key TagName

You will need to provide an SSH authentication method. This authentication method
should work for all instances that your tag or region filters select. Instances must
be routable from your local host.

To authenticate using username and password:

    lacework agent install ec2-ssh --ssh_username <your-user> --ssh_password <secret>

To authenticate using an identity file:

    lacework agent install ec2-ssh -i /path/to/your/key

The environment should contain AWS credentials in the following variables:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- AWS_SESSION_TOKEN (optional),
- AWS_REGION (optional)

This command will automatically add hosts with successful connections to
'~/.ssh/known_hosts' unless specified with '--trust_host_key=false'.`,
		RunE: installAWSSSH,
	}
)

func init() {
	// 'agent install ec2-ssh' flags
	agentInstallAWSSSHCmd.Flags().StringVar(&agentCmdState.InstallTagKey,
		"tag_key", "", "only install agents on infra with this tag key",
	)
	agentInstallAWSSSHCmd.Flags().StringSliceVar(&agentCmdState.InstallTag,
		"tag", []string{}, "only select instances with this tag",
	)
	agentInstallAWSSSHCmd.Flags().StringVarP(&agentCmdState.InstallIdentityFile,
		"identity_file", "i", defaultSshIdentityKey,
		"identity (private key) for public key authentication",
	)
	agentInstallAWSSSHCmd.Flags().StringVar(&agentCmdState.InstallAgentToken,
		"token", "", "agent access token",
	)
	agentInstallAWSSSHCmd.Flags().BoolVar(&agentCmdState.InstallTrustHostKey,
		"trust_host_key", true, "automatically add host keys to the ~/.ssh/known_hosts file",
	)
	agentInstallAWSSSHCmd.Flags().StringSliceVarP(&agentCmdState.InstallIncludeRegions,
		"include_regions", "r", []string{}, "list of regions to filter on",
	)
	agentInstallAWSSSHCmd.Flags().StringVar(&agentCmdState.InstallPassword,
		"ssh_password", "", "password for authentication",
	)
	agentInstallAWSSSHCmd.Flags().StringVar(&agentCmdState.InstallSshUser,
		"ssh_username", "", "username to login with",
	)
	agentInstallAWSSSHCmd.Flags().IntVar(&agentCmdState.InstallSshPort,
		"ssh_port", 22, "port to connect to on the remote host",
	)
}

func installAWSSSH(_ *cobra.Command, _ []string) error {
	runners, err := awsDescribeInstances()
	if err != nil {
		return err
	}

	wg := new(sync.WaitGroup)
	for _, runner := range runners {
		wg.Add(1)
		go func(runner *lwrunner.AWSRunner) {
			cli.Log.Debugw("runner info: ",
				"user", runner.Runner.User,
				"region", runner.Region,
				"az", runner.AvailabilityZone,
				"instance ID", runner.InstanceID,
				"hostname", runner.Runner.Hostname,
			)

			err := runner.Runner.UseIdentityFile(agentCmdState.InstallIdentityFile)
			if err != nil {
				cli.Log.Warnw("unable to use provided identity file", "err", err, "runner", runner.InstanceID)
			}

			if err := verifyAccessToRemoteHost(&runner.Runner); err != nil {
				cli.Log.Debugw("verifyAccessToRemoteHost failed", "err", err, "runner", runner.InstanceID)
			}

			if alreadyInstalled := isAgentInstalledOnRemoteHost(&runner.Runner); alreadyInstalled != nil {
				cli.Log.Debugw("agent already installed on host, skipping", "runner", runner.InstanceID)
			}

			token := agentCmdState.InstallAgentToken
			if token == "" {
				cli.Log.Debugw("agent token not provided", "runner", runner.InstanceID)
			}
			cmd := fmt.Sprintf("sudo sh -c \"curl -sSL %s | sh -s -- %s\"", agentInstallDownloadURL, token)
			err = runInstallCommandOnRemoteHost(&runner.Runner, cmd)
			if err != nil {
				cli.Log.Debugw("runInstallCommandOnRemoteHost failed", "err: ", err, "instance ID", runner.InstanceID)
			}
			wg.Done()
		}(runner)
	}
	wg.Wait()

	return nil
}
