package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Requires AWS credentials in the shell environment
func TestAwsFindRunnersToCapture(t *testing.T) {
	runners, err := awsFindRunnersToCapture()
	assert.NoError(t, err)
	assert.NotEmpty(t, runners)
}
