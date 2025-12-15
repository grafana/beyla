// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest

import (
	"os"
	"syscall"

	"github.com/grafana/jvmtools/jvm"
	"github.com/grafana/jvmtools/util"
)

var (
	jvmAttachFunc        = jvm.Jattach
	jvmAttachInitFunc    = initAttach
	jvmAttachCleanupFunc = cleanupAttach
)

func initAttach() (int, int, int) {
	myUID := syscall.Geteuid()
	myGID := syscall.Getegid()
	myPID := os.Getpid()

	return myUID, myGID, myPID
}

func cleanupAttach(myUID, myGID, myPID int) error {
	if err := syscall.Seteuid(myUID); err != nil {
		return err
	}
	if err := syscall.Setegid(myGID); err != nil {
		return err
	}

	util.EnterNS(myPID, "net")
	util.EnterNS(myPID, "ipc")
	util.EnterNS(myPID, "mnt")

	return nil
}
