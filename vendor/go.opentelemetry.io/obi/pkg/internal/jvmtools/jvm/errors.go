// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import "errors"

// ErrSignalWithheld reports that the attach handshake was not started because
// the target would not have acted on the signal that starts it, or would have
// been terminated by it. The reason is carried in the wrapped message.
var ErrSignalWithheld = errors.New("attach signal withheld")
