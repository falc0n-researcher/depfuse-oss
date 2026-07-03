package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepresentativeAffectedVersion(t *testing.T) {
	require.Equal(t, "3.3.1", representativeAffectedVersion("3.4.0"))
	require.Equal(t, "4.17.20", representativeAffectedVersion("4.17.21"))
	require.Equal(t, "1.68.1", representativeAffectedVersion("1.69.0"))
	require.Equal(t, "", representativeAffectedVersion(""))
	require.Equal(t, "", representativeAffectedVersion("not-a-version"))
}
