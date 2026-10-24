# Open Screen Library fork

This is a fork of Chromium's [Open Screen Library](https://chromium.googlesource.com/openscreen)
used for [Open Screen Protocol](https://github.com/w3c/openscreenprotocol)
interoperability work, mainly against the Go implementation in
[go-lp2p](https://github.com/backkem/go-lp2p).

## Branches

- **`main`** mirrors upstream `main` exactly. A [scheduled workflow](.github/workflows/sync-upstream.yml)
  fast-forwards it daily; nothing is ever committed to it directly.
- **`fork`** (this branch, the default) holds only this README and the sync
  workflow.
- **Feature branches** carry the changes, as a stack of small pull requests.
  Each PR targets the branch of the PR below it, and the bottom one targets
  `main`. Every PR is meant to be upstreamable on its own and follows the
  Google, Chromium and Open Screen C++ style rules.

## Working with the stack

The changes are developed and tested together, then split into one branch per
feature or fix. To test everything, check out the top branch of the stack.

When `main` moves, rebase the stack from the bottom up, for example with
`git rebase --update-refs main` on the top branch, and force-push each branch.

Upstreaming happens one PR at a time through Chromium's Gerrit
(`git cl upload`), starting from the bottom of the stack. Once a change lands
upstream, the sync brings it into `main` and its branch can be dropped from the
stack.

## Interop testing

Build `osp_demo` from the top of the stack and point the go-lp2p harness at it:

```sh
gn gen out/debug && ninja -C out/debug osp_demo
OPENSCREEN_OUT_DIR=$PWD/out/debug \
  go test -tags interop -v -count=1 ./openscreen-go/test/osp-demo-interop/   # in go-lp2p
```
