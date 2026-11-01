// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNetworkUnreachableWindows(t *testing.T) {
	// syscall.ENETUNREACH is a synthetic os-package error on Windows, not
	// the Winsock error returned by UDP writes.
	if !isNetworkUnreachableErr(&net.OpError{Op: "write", Net: "udp", Err: windows.WSAENETUNREACH}) {
		t.Fatal("did not recognize wrapped Winsock network-unreachable error")
	}
	if isNetworkUnreachableErr(windows.WSAEHOSTUNREACH) {
		t.Fatal("host-unreachable error must not trigger family fallback")
	}
}
