package beyla

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDKInject_Validate(t *testing.T) {
	t.Run("image_version set is valid", func(t *testing.T) {
		s := SDKInject{ImageVersion: "v1.0.0"}
		require.NoError(t, s.Validate())
	})

	t.Run("missing image_version is invalid", func(t *testing.T) {
		s := SDKInject{}
		err := s.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "image volume version is required")
	})
}

func TestSDKInject_PackageVersion(t *testing.T) {
	t.Run("returns sha256 hash of image_version", func(t *testing.T) {
		path := "v1.0.0"
		s := SDKInject{ImageVersion: path}
		h := sha256.Sum224([]byte(path))
		assert.Equal(t, hex.EncodeToString(h[:]), s.PackageVersion())
		assert.Len(t, s.PackageVersion(), 56) // 224-bit hash → 56 hex chars
	})

	t.Run("different image versions produce different versions", func(t *testing.T) {
		s1 := SDKInject{ImageVersion: "v1.0.0"}
		s2 := SDKInject{ImageVersion: "v1.0.1"}
		assert.NotEqual(t, s1.PackageVersion(), s2.PackageVersion())
	})
}
