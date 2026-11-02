// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"net/netip"
	"regexp"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

func TestPrintEndpointHTMLReceiveUDPAfterReselection(t *testing.T) {
	if !hasUDPTransport {
		t.Skip("requires UDP transport")
	}
	synctest.Test(t, func(t *testing.T) {
		addr := netip.MustParseAddrPort("192.0.2.1:51820")
		var pub key.NodePublic
		if err := pub.UnmarshalText([]byte("nodekey:0100000000000000000000000000000000000000000000000000000000000000")); err != nil {
			t.Fatal(err)
		}
		c := &Conn{logf: t.Logf, peerMap: newPeerMap()}
		ep := &endpoint{c: c, publicKey: pub, isWireguardOnly: true,
			lastSendExt: mono.Now(), lastSendAny: mono.Now(),
			endpointState: map[netip.AddrPort]*endpointState{addr: {}},
		}
		c.peerMap.byNodeKey[pub] = newPeerInfo(ep)
		pattern := regexp.MustCompile(`<p>lastRecvUDP: ([^ ]+) ago</p>`)
		render := func(want string) string {
			t.Helper()
			var out bytes.Buffer
			printEndpointHTML(&out, ep)
			m := pattern.FindStringSubmatch(out.String())
			if len(m) != 2 || m[1] != want {
				t.Errorf("lastRecvUDP=%v, want %q", m, want)
			}
			return out.String()
		}
		render("-") // A cold endpoint must not claim prior receive activity.
		incoming := &lazyEndpoint{c: c, src: epAddr{ap: addr}}
		incoming.InitiationMessagePublicKey(pub.Raw32())
		render("0s")
		time.Sleep(6 * time.Second) // Five-second receive trust plus the observation margin.
		render("6s")
		var status ipnstate.PeerStatus
		ep.populatePeerStatus(&status)
		if !ep.bestAddrAt.IsZero() {
			t.Fatal("test did not exercise status-triggered speculative reselection")
		}
		page := render("6s")
		t.Logf("AFTER_RESELECTION_HTML_BEGIN\n%s\nAFTER_RESELECTION_HTML_END", page)
		// Receive activity, not path selection, must refresh the reported age.
		incoming.InitiationMessagePublicKey(pub.Raw32())
		render("0s")
		time.Sleep(time.Second)
		render("1s")
		// UDP activity is visible even without external sends or WG callbacks.
		ep = &endpoint{}
		ep.lastRecvUDPAny.StoreAtomic(mono.Now())
		render("0s")
	})
}
