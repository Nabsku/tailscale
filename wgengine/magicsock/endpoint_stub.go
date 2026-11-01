// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build wasm || plan9

package magicsock

func isNetworkUnreachableErr(err error) bool {
	return false
}

// isBadEndpointErr checks if err is one which is known to report that an
// endpoint can no longer be sent to. It is not exhaustive, but covers known
// cases.
func isBadEndpointErr(err error) bool {
	return false
}
