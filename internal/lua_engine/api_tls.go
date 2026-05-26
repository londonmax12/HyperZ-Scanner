package lua_engine

import (
	"crypto/x509"
	"net"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// timeUnixRFC3339UTC mirrors time.Unix(ts, 0).UTC().Format(time.RFC3339)
// so the .lua port's rfc3339 helper returns the same string the Go check
// stamps into detail. Kept local to the bridge - the .lua port goes
// through ctx.tls.format_unix_rfc3339_utc rather than reaching for any
// Lua date formatter (gopher-lua's sandbox does not expose os.date).
func timeUnixRFC3339UTC(ts int64) string {
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

// buildTLSTable returns the ctx.tls helper namespace. tls-audit is the
// only check on the surface today; the helpers are organised around
// "give me the bytes the handshake produced" and let the .lua port
// decide severity / titles / dedupe shape from there. That keeps the
// per-version / per-cipher / per-expiry-window decisions in Lua where
// the rest of the check lives.
//
//	ctx.tls.handshake(addr, server_name?)
//	  -> (state_table, err_string)
//	  state_table = {
//	    version             = uint16,
//	    version_name        = "TLS 1.0" / "TLS 1.1" / "TLS 1.2" / ...,
//	    cipher_suite        = uint16,
//	    cipher_suite_name   = string,
//	    is_insecure_cipher  = bool,
//	    ocsp_response_present  = bool,
//	    handshake_sct_nonempty = bool,
//	    peer_certificates   = [cert_userdata...],
//	  }
//	  addr is host:port (the .lua port composes this from u.hostname +
//	  default 443 fallback - same as the Go check). err is non-nil on
//	  dial / handshake failure; state_table is nil in that case.
//
//	ctx.tls.now()
//	  -> unix_int seconds. Routes through TLSAuditNowUnix so a
//	     SetTLSAuditNowForTest swap is observed in the same Run.
//
//	ctx.tls.dial_timeout_seconds()    -> 10
//	ctx.tls.expiry_urgent_window_s()  -> 14*24*3600
//	ctx.tls.expiry_soon_window_s()    -> 30*24*3600
//	  Constants the Lua port reads each Run so a Go-side timing tweak
//	  propagates without any Lua edits.
//
// Cert userdata exposes per-cert accessors that the .lua port uses to
// build expiry / hostname / SCT findings:
//
//	cert:subject_cn()           -> string
//	cert:not_before()           -> unix_int
//	cert:not_after()            -> unix_int
//	cert:dns_names()            -> array of string
//	cert:has_embedded_sct()     -> bool
//	cert:verifies_hostname(host) -> bool
func buildTLSTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("handshake", L.NewFunction(tlsHandshake))
	t.RawSetString("now", L.NewFunction(tlsNow))
	t.RawSetString("dial_timeout_seconds", L.NewFunction(tlsDialTimeoutSeconds))
	t.RawSetString("expiry_urgent_window_s", L.NewFunction(tlsExpiryUrgentWindowSeconds))
	t.RawSetString("expiry_soon_window_s", L.NewFunction(tlsExpirySoonWindowSeconds))
	t.RawSetString("format_unix_rfc3339_utc", L.NewFunction(tlsFormatUnixRFC3339UTC))
	return t
}

// tlsFormatUnixRFC3339UTC renders a unix-second timestamp as the same
// RFC 3339 / "Z" form the Go check uses to stamp expiry windows into
// finding detail (time.Time.UTC().Format(time.RFC3339)). gopher-lua's
// sandbox does not expose os.date, so the .lua port goes through this
// helper rather than rolling its own zone-aware formatter.
func tlsFormatUnixRFC3339UTC(L *lua.LState) int {
	ts := L.CheckInt64(1)
	out := timeUnixRFC3339UTC(ts)
	L.Push(lua.LString(out))
	return 1
}

// tlsHandshake implements ctx.tls.handshake(addr, server_name?). Goes
// through TLSAuditHandshakeLua which dials through the same
// tlsAuditDial indirection the Go check uses, so a test that swaps
// the dial sees both implementations route through the override.
func tlsHandshake(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("ctx.tls.handshake called outside a check run"))
		return 2
	}
	addr := requireString(L, 1)
	serverName := optString(L, 2, "")
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			serverName = host
		} else {
			serverName = addr
		}
	}
	res, err := TLSAuditHandshakeLua(env.ctx, addr, serverName)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	out := L.NewTable()
	out.RawSetString("version", lua.LNumber(res.Version))
	out.RawSetString("version_name", lua.LString(res.VersionLabel))
	out.RawSetString("cipher_suite", lua.LNumber(res.CipherSuite))
	out.RawSetString("cipher_suite_name", lua.LString(res.CipherSuiteName))
	out.RawSetString("is_insecure_cipher", lua.LBool(res.IsInsecureCipher))
	out.RawSetString("ocsp_response_present", lua.LBool(res.OCSPResponsePresent))
	out.RawSetString("handshake_sct_nonempty", lua.LBool(res.HandshakeSCTNonEmpty))
	certs := L.NewTable()
	for i, c := range res.PeerCertificates {
		certs.RawSetInt(i+1, pushTLSCert(L, c))
	}
	out.RawSetString("peer_certificates", certs)
	L.Push(out)
	return 1
}

func tlsNow(L *lua.LState) int {
	L.Push(lua.LNumber(TLSAuditNowUnix()))
	return 1
}

func tlsDialTimeoutSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(TLSAuditDialTimeoutSeconds()))
	return 1
}

func tlsExpiryUrgentWindowSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(TLSAuditExpiryUrgentWindowSeconds()))
	return 1
}

func tlsExpirySoonWindowSeconds(L *lua.LState) int {
	L.Push(lua.LNumber(TLSAuditExpirySoonWindowSeconds()))
	return 1
}

// tlsCertUserData wraps an *x509.Certificate so the .lua port reads
// the subject / dates / dns / SCT extension through stable methods
// instead of poking at a Lua table the bridge would have to keep in
// sync with the Go struct. Lifetime is the single Run that produced
// it; the bridge does not retain pointers across Runs.
type tlsCertUserData struct {
	c *x509.Certificate
}

func pushTLSCert(L *lua.LState, c *x509.Certificate) lua.LValue {
	ud := L.NewUserData()
	ud.Value = &tlsCertUserData{c: c}
	ud.Metatable = ensureTLSCertMT(L)
	return ud
}

const mtTLSCert = "__hyperz_mt_tls_cert"

func ensureTLSCertMT(L *lua.LState) *lua.LTable {
	if mt, ok := L.G.Registry.RawGetString(mtTLSCert).(*lua.LTable); ok {
		return mt
	}
	mt := L.NewTable()
	methods := L.NewTable()
	methods.RawSetString("subject_cn", L.NewFunction(tlsCertSubjectCN))
	methods.RawSetString("not_before", L.NewFunction(tlsCertNotBefore))
	methods.RawSetString("not_after", L.NewFunction(tlsCertNotAfter))
	methods.RawSetString("dns_names", L.NewFunction(tlsCertDNSNames))
	methods.RawSetString("has_embedded_sct", L.NewFunction(tlsCertHasEmbeddedSCT))
	methods.RawSetString("verifies_hostname", L.NewFunction(tlsCertVerifiesHostname))
	mt.RawSetString("__index", methods)
	L.G.Registry.RawSetString(mtTLSCert, mt)
	return mt
}

func tlsCertFromArg(L *lua.LState) *tlsCertUserData {
	ud, ok := L.CheckUserData(1).Value.(*tlsCertUserData)
	if !ok {
		L.ArgError(1, "expected tls cert userdata")
	}
	return ud
}

func tlsCertSubjectCN(L *lua.LState) int {
	c := tlsCertFromArg(L).c
	if c == nil {
		L.Push(lua.LString(""))
		return 1
	}
	L.Push(lua.LString(c.Subject.CommonName))
	return 1
}

func tlsCertNotBefore(L *lua.LState) int {
	c := tlsCertFromArg(L).c
	if c == nil {
		L.Push(lua.LNumber(0))
		return 1
	}
	L.Push(lua.LNumber(c.NotBefore.Unix()))
	return 1
}

func tlsCertNotAfter(L *lua.LState) int {
	c := tlsCertFromArg(L).c
	if c == nil {
		L.Push(lua.LNumber(0))
		return 1
	}
	L.Push(lua.LNumber(c.NotAfter.Unix()))
	return 1
}

func tlsCertDNSNames(L *lua.LState) int {
	c := tlsCertFromArg(L).c
	if c == nil {
		L.Push(L.NewTable())
		return 1
	}
	L.Push(pushStringList(L, c.DNSNames))
	return 1
}

func tlsCertHasEmbeddedSCT(L *lua.LState) int {
	c := tlsCertFromArg(L).c
	L.Push(lua.LBool(TLSAuditCertEmbedsSCT(c)))
	return 1
}

func tlsCertVerifiesHostname(L *lua.LState) int {
	c := tlsCertFromArg(L).c
	host := requireString(L, 2)
	L.Push(lua.LBool(TLSAuditCertVerifyHostname(c, host)))
	return 1
}
