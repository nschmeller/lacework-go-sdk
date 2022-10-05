package cmd

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/lacework/go-sdk/lwrunner"
	"github.com/stretchr/testify/assert"
)

// Requires AWS credentials in the shell environment
// Lists runners, sends keys, attempts to connect
// Example command to run:
// `aws-vault exec default -- go test -run TestAwsEC2ICFindRunnersToCapture`
// If AWS credentials are already present in the shell environment, only use:
// `go test -run TestAwsEC2ICFindRunnersToCapture`
func TestAwsEC2ICFindRunnersToCapture(t *testing.T) {
	if _, ok := os.LookupEnv("AWS_SECRET_ACCESS_KEY"); !ok {
		t.Skip("aws credentials not found in environment, skipping test")
	}

	agentCmdState.InstallTrustHostKey = true
	agentCmdState.CTFInfraTagKey = "CaptureTheFlagPlayer"
	cli.NonInteractive()

	runners, err := awsFindRunnersToCapture()
	assert.NoError(t, err)

	wg := new(sync.WaitGroup)
	for _, runner := range runners {
		wg.Add(1)
		go func(runner *lwrunner.AWSRunner) {
			out := fmt.Sprintf("--------- Runner ---------\nRegion: %v\nInstance ID: %v\n", runner.Region, runner.InstanceID)

			err = runner.SendAndUseIdentityFile()
			assert.NoError(t, err)

			err = verifyAccessToRemoteHost(&runner.Runner)
			assert.NoError(t, err)

			if alreadyInstalled := isAgentInstalledOnRemoteHost(&runner.Runner); alreadyInstalled != nil {
				out += alreadyInstalled.Error() + "\n"
			}

			fmt.Println(out)
			wg.Done()
		}(runner)
	}
	wg.Wait()
}
