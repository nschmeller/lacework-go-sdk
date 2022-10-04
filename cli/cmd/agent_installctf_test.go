package cmd

import (
	"fmt"
	"sync"
	"testing"

	"github.com/lacework/go-sdk/lwrunner"
	"github.com/stretchr/testify/assert"
)

// Requires AWS credentials in the shell environment
// Lists runners, sends keys, attempts to connect
func TestAwsFindRunnersToCapture(t *testing.T) {
	// agentCmdState.CTFInfraTag = []string{
	// 	"CaptureTheFlagPlayer",
	// 	"guid123",
	// }
	agentCmdState.InstallTrustHostKey = true
	agentCmdState.CTFInfraTagKey = "CaptureTheFlagPlayer"
	cli.NonInteractive()

	runners, err := awsFindRunnersToCapture()
	assert.NoError(t, err)
	assert.NotEmpty(t, runners)

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
				out += "agent already installed on this runner\n"
			}

			fmt.Println(out)
			wg.Done()
		}(runner)
	}
	wg.Wait()
}
