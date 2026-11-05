# Mullvad image channel

`ghcr.io/nabsku/tailscale:mullvad` is reserved for this fork's reviewed Mullvad
patch payload. It is a moving alias, not a Tailscale release or an upstream
`latest` channel. Consumers can track its digest; production references should
remain digest-pinned. Publishing the alias does not update a deployment.

The workflow only promotes an existing, fixed digest in the same package with
[Docker Buildx imagetools](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/).
It does not build source, pull or run an image, or change VPN configuration.
`--prefer-index=false` preserves the source manifest instead of wrapping the
current single manifest in an index. The workflow reads back the raw manifest
and checks its SHA-256. It does not add platforms or change image contents.

## Initial reviewed payload

- Source commit: `dc8cd243c8f6464c58e741d7355f4555e6494bb0` on
  [`fix/mullvad-peer-receive-observation`](https://github.com/Nabsku/tailscale/tree/dc8cd243c8f6464c58e741d7355f4555e6494bb0).
- Existing tag: `ghcr.io/nabsku/tailscale:mullvad-peer-receive-dc8cd243c`.
- Fixed source digest:
  `sha256:f1594058f5a1c3b61bd9da683925676a200f785951f4d5eaa9859d27afcb8dc3`.

This is the owner-identified deployed artifact. Anonymous manifest reads on
2026-11-05 confirmed that the tag and digest return identical bytes. The manifest
has no source revision annotation; that check confirms artifact identity, not
build provenance or runtime correctness. No image layers were read for it.

The source is `v1.104.4` (`27047635f`) plus these cumulative changes:

- `078b3282e`: first-send address-family hints for WireGuard-only peers.
- `871393139`: prefer the local family on single-stack networks, including when
  restricted egress makes netcheck report both families missing.
- `379b6d82f`: try the other family once on network-unreachable errors, including
  idle reconnects; keep ordinary-peer and peer-relay behavior unchanged.
- `dc8cd243c`: report stable UDP receive age after path reselection.

`main` does not contain this patch chain. Never replace the source with a build
of `main`, an upstream/vanilla image, or a tag selected by sorting commit hashes.
For each future channel move, first review the patch source and artifact mapping.
A PR must update the workflow's fixed `SOURCE`, its offline test expectation, and
this payload record. Retain these changes or explicitly reviewed equivalents.
There is no automatic source selection or patch-branch build in this workflow.

## Publication requires separate approval

Opening or merging the publisher PR is not permission to publish. The alias is
not created by either action. Before each publication:

1. Obtain owner approval for the exact source digest and `:mullvad` alias move.
2. After approval, enable the repository variable
   `MULLVAD_CHANNEL_PUBLISH_ENABLED` with the exact value `true`. An absent or
   different value skips the job. Keep the gate disabled between promotions.
3. Ensure the existing GHCR package permits this repository's `GITHUB_TOKEN` to
   write. Any required package-access change needs separate approval; do not
   introduce a personal access token.
4. Manually run **Promote Mullvad image channel** from `main` in `Nabsku/tailscale`,
   with confirmation `publish-mullvad`. No push, PR, release, or schedule event
   can run the workflow. Other repositories and refs cannot run its publish job.
5. Check the digest verification result, then disable the variable. On failure,
   inspect the alias before retrying or consuming it: a write can have succeeded
   before read-back failed. The workflow does not automatically roll back.

The job uses only `packages: write`; the pinned login action manages login and
logout with the job token. No checkout or image build is needed. Buildx is
already installed on the hosted `ubuntu-24.04` runner.

## Offline check

Run `ruby .github/scripts/test-mullvad-channel.rb`. It checks the manual gates,
permissions, fixed artifact, action pin, Bash syntax, and promotion success/error
paths with a local Docker stub. It cannot verify GHCR permissions, Actions event
execution, or the real registry write. Do not dispatch to test this PR.
