package ebpfconvenience

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// This file contains convenience functions around the cilum/ebpf
// CollectionSpec.Variables API.
// This wrapper has been deprecated in the main cilium/ebpf codebase.

// MissingConstantsError is returned by [ebpf.CollectionSpec.RewriteConstants].
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return "some constants are missing from .rodata: " + strings.Join(m.Constants, ", ")
}

// RewriteConstants replaces the value of multiple constants.
//
// The constant must be defined like so in the C program:
//
//	volatile const type foobar;
//	volatile const type foobar = default;
//
// Replacement values must be of the same length as the C sizeof(type).
// If necessary, they are marshaled according to the same rules as
// map values.
//
// From Linux 5.5 the verifier will use constants to eliminate dead code.
//
// Returns an error wrapping [MissingConstantsError] if a constant doesn't exist.
func RewriteConstants(cs *ebpf.CollectionSpec, consts map[string]any) error {
	var missing []string
	for n, c := range consts {
		v, ok := cs.Variables[n]
		if !ok {
			missing = append(missing, n)
			continue
		}

		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", n)
		}

		if err := v.Set(c); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", n, err)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %w", &MissingConstantsError{Constants: missing})
	}

	return nil
}
