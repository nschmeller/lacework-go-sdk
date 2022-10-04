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

package lwrunner

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2instanceconnect"
	"golang.org/x/crypto/ssh"
)

type AWSRunner struct {
	Runner           Runner
	Region           string
	AvailabilityZone string
	InstanceID       string
}

func NewAWSRunner(user, host, region, availabilityZone, instanceID string, callback ssh.HostKeyCallback) *AWSRunner {
	if os.Getenv("LW_SSH_USER") != "" {
		user = os.Getenv("LW_SSH_USER")
	}

	defaultCallback, err := DefaultKnownHosts()
	if err == nil && callback == nil {
		callback = defaultCallback
	}

	runner := New(user, host, callback)

	return &AWSRunner{
		*runner,
		region,
		availabilityZone,
		instanceID,
	}
}

func (run AWSRunner) SendAndUseIdentityFile() error {
	pubBytes, privBytes, err := GetKeyBytes()
	if err != nil {
		return err
	}

	err = run.SendPublicKey(pubBytes)
	if err != nil {
		return err
	}

	signer, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		return err
	}
	run.Runner.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}

	return nil
}

// Helper function to send a public key to a test instance. Uses
// EC2InstanceConnect. The AWS account used to run the tests must
// have EC2InstanceConnect permissions attached to its IAM role.
func (run AWSRunner) SendPublicKey(pubBytes []byte) error {
	sess := session.Must(session.NewSession(
		&aws.Config{
			Region:                        aws.String(run.Region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		},
	))
	svc := ec2instanceconnect.New(sess)

	input := &ec2instanceconnect.SendSSHPublicKeyInput{
		AvailabilityZone: &run.AvailabilityZone,
		InstanceId:       &run.InstanceID,
		InstanceOSUser:   aws.String(run.Runner.User),
		SSHPublicKey:     aws.String(string(pubBytes)),
	}

	_, err := svc.SendSSHPublicKey(input)
	if err != nil {
		return err
	}

	return nil
}
