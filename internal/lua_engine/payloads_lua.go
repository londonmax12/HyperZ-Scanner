package lua_engine

// This file exposes the curated payload catalogues to the Lua bridge.
// Sibling to payloads.go: every per-class one-liner forwards into
// PayloadsFor(class) via the shared payloadsAsLuaShape projector so
// the Lua port iterates a stable {Name, Template} list in the same
// order the Go side produces.

// SQLiErrorPayload is the {Name, Template} pair the bridge marshals
// into Lua tables for every payload-catalogue helper below. The name
// is historical (the first caller was SQLiErrorPayloads); the type is
// generic across every PayloadClass exposed via payloadsAsLuaShape.
type SQLiErrorPayload struct {
	Name     string
	Template string
}

// SQLiErrorPayloads returns the curated PayloadSQLiError catalogue in
// the same order PayloadsFor produces it. The Lua port iterates these
// in order so its first-hit-wins behavior matches the Go check 1:1.
func SQLiErrorPayloads() []SQLiErrorPayload {
	return payloadsAsLuaShape(PayloadSQLiError)
}

// payloadsAsLuaShape returns PayloadsFor(class) re-shaped into the
// {Name, Template} pair the bridge marshals into Lua tables. Every
// caller wants the same projection (name + template, drop the class
// tag the Go side already conditioned on), so centralising it keeps
// the per-class helpers below one-liners and avoids per-call slice
// shape drift between the seven payload classes.
func payloadsAsLuaShape(class PayloadClass) []SQLiErrorPayload {
	src := PayloadsFor(class)
	out := make([]SQLiErrorPayload, 0, len(src))
	for _, p := range src {
		out = append(out, SQLiErrorPayload{Name: p.Name, Template: p.Template})
	}
	return out
}

// TraversalPayloadsLua / SQLiTimePayloadsLua / CmdInjectPayloadsLua /
// CmdInjectBlindPayloadsLua / XSSPayloadsLua mirror SQLiErrorPayloads
// for the other PayloadClass values the Lua bridge surfaces. Each is
// a one-liner so the Lua port iterates a stable list in the same order
// the Go side already produces.
func TraversalPayloadsLua() []SQLiErrorPayload      { return payloadsAsLuaShape(PayloadTraversal) }
func SQLiTimePayloadsLua() []SQLiErrorPayload       { return payloadsAsLuaShape(PayloadSQLiTime) }
func CmdInjectPayloadsLua() []SQLiErrorPayload      { return payloadsAsLuaShape(PayloadCmdInject) }
func CmdInjectBlindPayloadsLua() []SQLiErrorPayload { return payloadsAsLuaShape(PayloadCmdInjectBlind) }
func XSSPayloadsLua() []SQLiErrorPayload            { return payloadsAsLuaShape(PayloadXSS) }

// SQLiBooleanPairsLua exposes the curated boolean-pair set the Lua
// port iterates. Same projection as the underlying SQLiBooleanPairs;
// re-exported with the Lua suffix so the bridge can read every payload
// catalogue under a uniform name.
type LuaBooleanPair struct {
	Name  string
	True  string
	False string
}

func SQLiBooleanPairsLua() []LuaBooleanPair {
	src := SQLiBooleanPairs()
	out := make([]LuaBooleanPair, 0, len(src))
	for _, p := range src {
		out = append(out, LuaBooleanPair{Name: p.Name, True: p.True, False: p.False})
	}
	return out
}
