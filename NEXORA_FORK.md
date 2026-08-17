# nexora-openvpn

A thin fork of [`github.com/sagernet/sing-openvpn`](https://github.com/sagernet/sing-openvpn)
used by [nexora-node](https://github.com/Nexora-VPN/nexora-node).

The Go module path is intentionally left as `github.com/sagernet/sing-openvpn`
so it can be dropped in via a `replace` directive without touching any import in
sing-box or the node:

```
replace github.com/sagernet/sing-openvpn => github.com/Nexora-VPN/nexora-openvpn <version>
```

## The only change

The fork exposes `Server.SourceUser(addr netip.Addr) (string, bool)`, which maps a
client's assigned VPN (tunnel) source address to its authenticated username. The
node's local `openvpn-server` endpoint uses it to set `metadata.User` on each
routed connection so per-user traffic accounting works — upstream sing-openvpn
keeps that mapping internal (the route registry stores the inner
`*tlsPeerSession`, whose embedding gives no back-reference to the outer
`tlsServerSession` that holds the username), and the upstream sing-box
`openvpn-server` endpoint never tags the user, so its traffic is otherwise never
attributed to a user.

Three touch points (grep for `Nexora`):
- `peer_session.go` — one field on `tlsPeerSession`: `nexoraUsername atomic.Pointer[string]` (+ the `sync/atomic` import).
- `server_session.go` — one line in `lockAuthenticatedUsername`: `s.tlsPeerSession.storeNexoraUsername(username)`.
- `source_user.go` — the new file: `SourceUser`, `usernameOf`, `storeNexoraUsername`, `loadNexoraUsername`.

Everything else is a verbatim copy of the upstream release below.

## Syncing to a newer upstream

1. `go list -m -f '{{.Dir}}' github.com/sagernet/sing-openvpn` in a node checkout
   pinned to the new sing-box version.
2. Copy that directory over this one (keep `.git`, `source_user.go`, this file).
3. Re-apply the two in-place edits above (the field + the one-line store call),
   and confirm `source_user.go` still compiles (field names `routes`, `access`,
   `session` unchanged).
4. Tag a new version and update the node's `replace` directive.

Upstream base: `github.com/sagernet/sing-openvpn v0.0.0-20260729104525-103eb5fe5eb6`
— the version pinned by sing-box v1.14.0-beta.15 **and** v1.14.0-beta.17 (both
pin the same sing-openvpn, so bumping the node from beta.15→beta.17 needed no
change here).
