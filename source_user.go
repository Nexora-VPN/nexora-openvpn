package openvpn

import "net/netip"

// This file is the ONLY addition Nexora makes on top of upstream
// github.com/sagernet/sing-openvpn. It exposes the authenticated username behind
// a client's assigned VPN (tunnel) source address so the sing-box server
// endpoint can tag each routed connection with metadata.User for per-user
// traffic accounting — which upstream does not do for openvpn-server.
//
// Keep this the sole diff so re-syncing to a newer upstream sing-openvpn is a
// clean copy + re-add of this one file.

// SourceUser returns the authenticated username of the client that owns the
// given VPN source address (the inner tunnel IP seen on routed connections), and
// whether such a client was found. Safe to call concurrently.
func (s *Server) SourceUser(address netip.Addr) (string, bool) {
	if s == nil || s.routes == nil {
		return "", false
	}
	return s.routes.usernameOf(address)
}

// usernameOf resolves a VPN source address to its owning session's authenticated
// username under the registry's read lock.
func (r *peerRouteRegistry) usernameOf(address netip.Addr) (string, bool) {
	if !address.IsValid() {
		return "", false
	}
	r.access.RLock()
	defer r.access.RUnlock()
	route, ok := r.routes[address]
	if !ok || route.session == nil {
		return "", false
	}
	return route.session.loadNexoraUsername()
}

// storeNexoraUsername records the authenticated username on the peer session.
// Called from tlsServerSession.lockAuthenticatedUsername.
func (s *tlsPeerSession) storeNexoraUsername(username string) {
	u := username
	s.nexoraUsername.Store(&u)
}

// loadNexoraUsername returns the authenticated username, if auth has completed.
func (s *tlsPeerSession) loadNexoraUsername() (string, bool) {
	if p := s.nexoraUsername.Load(); p != nil && *p != "" {
		return *p, true
	}
	return "", false
}
