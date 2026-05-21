package beyla

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDKInject_Validate(t *testing.T) {
	t.Run("image_volume_path set is valid", func(t *testing.T) {
		s := SDKInject{ImageVolumePath: "/mnt/image"}
		require.NoError(t, s.Validate())
	})

	t.Run("missing image_volume_path is invalid", func(t *testing.T) {
		s := SDKInject{}
		err := s.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "image volume path is required")
	})
}

func TestSDKInject_PackageVersion(t *testing.T) {
	t.Run("returns sha256 hash of image_volume_path", func(t *testing.T) {
		path := "/mnt/oci/image"
		s := SDKInject{ImageVolumePath: path}
		h := sha256.Sum224([]byte(path))
		assert.Equal(t, hex.EncodeToString(h[:]), s.PackageVersion())
		assert.Len(t, s.PackageVersion(), 56) // 224-bit hash → 56 hex chars
	})

	t.Run("different image paths produce different versions", func(t *testing.T) {
		s1 := SDKInject{ImageVolumePath: "/mnt/image/v1"}
		s2 := SDKInject{ImageVolumePath: "/mnt/image/v2"}
		assert.NotEqual(t, s1.PackageVersion(), s2.PackageVersion())
	})
}

func TestSDKInject_UsesImageVolume(t *testing.T) {
	t.Run("returns true when image_volume_path is set", func(t *testing.T) {
		s := SDKInject{ImageVolumePath: "/mnt/image"}
		assert.True(t, s.UsesImageVolume())
	})

	t.Run("returns false when image_volume_path is empty", func(t *testing.T) {
		s := SDKInject{}
		assert.False(t, s.UsesImageVolume())
	})
}
