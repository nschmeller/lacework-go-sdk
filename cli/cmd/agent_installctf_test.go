package cmd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Requires AWS credentials in the shell environment
func TestAwsFindRunnersToCapture(t *testing.T) {
	runners, err := awsFindRunnersToCapture()
	assert.NoError(t, err)
	assert.NotEmpty(t, runners)
	for _, runner := range runners {
		fmt.Println("--------- Runner ---------")
		fmt.Println(runner.Region)
		fmt.Println(runner.InstanceID)
	}
}
