package openvpn

import "net/netip"

// This file is the ONLY addition Nexora makes on top of upstream
// github.com/sagernet/sing-openvpn. It exposes the authenticated username behind
// a client's assigned VPN (tunnel) source address so the sing-box server
// endpoint can tag each routed connection with metadata.User for per-user
// traffic accounting — which upstream does not do for openvpn-server — hands
// the node the *Server that answers it (ServerAnnouncer), and lets the node
// change the server's users while it runs (SetAuthenticator, DisconnectUsers).
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

// ServerAnnouncer is implemented by a ServerOptions.Logger that wants the
// *Server NewServer builds. sing-box creates the server inside its endpoint's
// Start and keeps it in an unexported field; the logger is the one thing the
// node hands that endpoint which reaches NewServer, so the node passes a
// logger that also implements this and learns the server without reaching
// into sing-box's fields.
type ServerAnnouncer interface {
	AnnounceOpenVPNServer(server *Server)
}

func announceServer(logger any, server *Server) {
	if announcer, ok := logger.(ServerAnnouncer); ok {
		announcer.AnnounceOpenVPNServer(server)
	}
}

// SetAuthenticator replaces the username/password check of a running server
// (v0.1.2). It applies to every login from then on; a nil authenticator
// accepts any username and password, as a server built without one does.
// Sessions already in are not touched: DisconnectUsers ends the ones that
// should not stay. Together they let the node change an OpenVPN server's users
// without rebuilding it, which drops every client until its ping-restart runs
// out.
func (s *Server) SetAuthenticator(authenticator UserPassAuthenticator) {
	s.nexoraAuthenticator.Store(&authenticator)
}

// authenticator is the check a login goes through: the one SetAuthenticator
// gave, else the one the server was built with.
func (s *Server) authenticator() UserPassAuthenticator {
	if p := s.nexoraAuthenticator.Load(); p != nil {
		return *p
	}
	return s.options.Authentication.Authenticator
}

// DisconnectUsers closes every TLS session authenticated as a username keep
// refuses, and returns how many it closed (v0.1.2). A static-key server has no
// usernames and closes nothing.
func (s *Server) DisconnectUsers(keep func(username string) bool) int {
	if s == nil || s.tls == nil {
		return 0
	}
	s.tls.sessionAccess.RLock()
	var closing []*tlsServerSession
	for _, session := range s.tls.sessionByPeer {
		if username, ok := session.tlsPeerSession.loadNexoraUsername(); ok && !keep(username) {
			closing = append(closing, session)
		}
	}
	s.tls.sessionAccess.RUnlock()
	for _, session := range closing {
		_ = session.Close()
	}
	return len(closing)
}
