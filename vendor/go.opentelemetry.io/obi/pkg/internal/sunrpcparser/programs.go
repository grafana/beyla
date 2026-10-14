// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sunrpcparser // import "go.opentelemetry.io/obi/pkg/internal/sunrpcparser"

// Well-known ONC RPC program numbers used for onc_rpc.program.name.
//
// Sources: [RFC 5531] (RPC model), program numbers assigned in the RPC
// literature and Linux/NFS deployments (portmapper 100000, NFS 100003, mount
// 100005, etc.). See also IANA "RPC Program Numbers" and /etc/rpc on typical
// Unix systems.
//
// [RFC 5531]: https://datatracker.ietf.org/doc/html/rfc5531
const (
	ProgramPortmapper = 100000
	ProgramRstat      = 100001
	ProgramRusers     = 100002
	ProgramNFS        = 100003
	ProgramYpbind     = 100007
	ProgramMount      = 100005
	ProgramNFSACL     = 100227
	ProgramNlockmgr   = 100021
)

func ProgramName(prog uint32) string {
	switch prog {
	case ProgramPortmapper:
		return "portmapper"
	case ProgramRstat:
		return "rstat"
	case ProgramRusers:
		return "rusers"
	case ProgramNFS:
		return "nfs"
	case ProgramYpbind:
		return "ypbind"
	case ProgramMount:
		return "mount"
	case ProgramNFSACL:
		return "nfsacl"
	case ProgramNlockmgr:
		return "nlockmgr"
	default:
		return ""
	}
}

func procedureName(_ uint32, _ uint32) string {
	return ""
}

// AuthFlavorName returns a stable label for an RPC authentication flavor.
func AuthFlavorName(flavor uint32) string {
	switch flavor {
	case authNull:
		return "auth_null"
	case authUnix:
		return "auth_unix"
	case authShort:
		return "auth_short"
	case authDES:
		return "auth_des"
	case authKerb:
		return "auth_kerb"
	case authRSA:
		return "auth_rsa"
	case authRPCSECgss:
		return "rpcsec_gss"
	default:
		return ""
	}
}
