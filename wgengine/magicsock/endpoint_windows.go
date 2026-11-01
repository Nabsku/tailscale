// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

var errNETUNREACH error = syscall.ENETUNREACH
var errWSANETUNREACH error = windows.WSAENETUNREACH

func isNetworkUnreachableErr(err error) bool {
	return errors.Is(err, errNETUNREACH) || errors.Is(err, errWSANETUNREACH)
}
