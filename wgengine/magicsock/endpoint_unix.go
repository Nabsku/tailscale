// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !wasm && !plan9 && !windows

package magicsock

import (
	"errors"
	"syscall"
)

var errNETUNREACH error = syscall.ENETUNREACH

func isNetworkUnreachableErr(err error) bool {
	return errors.Is(err, errNETUNREACH)
}
