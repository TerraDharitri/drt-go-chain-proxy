package data

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsValidDcdtPath(t *testing.T) {
	testCases := []struct {
		input  string
		output bool
	}{
		{
			input:  FungibleTokens,
			output: true,
		},
		{
			input:  SemiFungibleTokens,
			output: true,
		},
		{
			input:  NonFungibleTokens,
			output: true,
		},
		{
			input:  "invalid token type",
			output: false,
		},
		{
			input:  "",
			output: false,
		},
	}

	for _, tc := range testCases {
		res := IsValidDcdtPath(tc.input)
		require.Equal(t, tc.output, res)
	}
}
