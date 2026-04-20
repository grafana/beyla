package beyla

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDKInject_Validate(t *testing.T) {
	tests := []struct {
		name    string
		inject  SDKInject
		wantErr string
	}{
		{
			name: "image_volume_path with host_mount_path is invalid",
			inject: SDKInject{
				ImageVolumePath: "/mnt/image",
				HostMountPath:   "/mnt/host",
			},
			wantErr: "image_volume_path and host_mount_path are mutually exclusive",
		},
		{
			name: "image_volume_path with sdk_package_version is invalid",
			inject: SDKInject{
				ImageVolumePath: "/mnt/image",
				SDKPkgVersion:   "v1.2.3",
			},
			wantErr: "image_volume_path and sdk_package_version are mutually exclusive",
		},
		{
			name: "image_volume_path alone is valid",
			inject: SDKInject{
				ImageVolumePath: "/mnt/image",
			},
		},
		{
			name:    "no image_volume_path and no sdk_package_version is invalid",
			inject:  SDKInject{},
			wantErr: "sdk_package_version must be supplied",
		},
		{
			name: "invalid sdk_package_version format is invalid",
			inject: SDKInject{
				SDKPkgVersion: "1.2.3", // missing 'v' prefix
			},
			wantErr: "sdk_package_version must be in valid semantic versioning format",
		},
		{
			name: "manage_sdk_versions without host_mount_path is invalid",
			inject: SDKInject{
				SDKPkgVersion:     "v1.2.3",
				ManageSDKVersions: true,
			},
			wantErr: "host_mount_path must be supplied",
		},
		{
			name: "valid config without manage_sdk_versions",
			inject: SDKInject{
				SDKPkgVersion: "v1.2.3",
			},
		},
		{
			name: "valid config with manage_sdk_versions and host_mount_path",
			inject: SDKInject{
				SDKPkgVersion:     "v1.2.3",
				ManageSDKVersions: true,
				HostMountPath:     "/mnt/host",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.inject.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSDKInject_PackageVersion(t *testing.T) {
	t.Run("returns sha256 hash of image_volume_path when set", func(t *testing.T) {
		path := "/mnt/oci/image"
		s := SDKInject{ImageVolumePath: path}
		h := sha256.Sum224([]byte(path))
		expected := fmt.Sprintf("%x", h)
		assert.Equal(t, expected, s.PackageVersion())
		assert.Len(t, s.PackageVersion(), 56) // 224-bit hash → 56 hex chars
	})

	t.Run("different image paths produce different versions", func(t *testing.T) {
		s1 := SDKInject{ImageVolumePath: "/mnt/image/v1"}
		s2 := SDKInject{ImageVolumePath: "/mnt/image/v2"}
		assert.NotEqual(t, s1.PackageVersion(), s2.PackageVersion())
	})

	t.Run("returns sdk_package_version when no image_volume_path", func(t *testing.T) {
		s := SDKInject{SDKPkgVersion: "v1.2.3"}
		assert.Equal(t, "v1.2.3", s.PackageVersion())
	})

	t.Run("returns empty string when both fields are unset", func(t *testing.T) {
		s := SDKInject{}
		assert.Equal(t, "", s.PackageVersion())
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
