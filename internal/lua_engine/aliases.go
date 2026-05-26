// Aliases re-export the public surface of internal/core inside the
// lua_engine package so the bulk of the helper / parser / probe code
// migrated out of internal/checks can keep using bare type and
// function names (`Check`, `Finding`, `MakeKey`, `SeverityHigh`, ...)
// without each call site needing a `core.` prefix. The single source
// of truth for these types is internal/core; this file is a thin
// re-export layer so the migration touches the minimum number of
// lines inside the moved files.
package lua_engine

import "github.com/londonmax12/hyperz/internal/core"

type (
	Severity      = core.Severity
	Level         = core.Level
	Scope         = core.Scope
	Evidence      = core.Evidence
	Exchange      = core.Exchange
	Finding       = core.Finding
	Check         = core.Check
	OOBCheck      = core.OOBCheck
	TwoPhaseCheck = core.TwoPhaseCheck
	Budgeted      = core.Budgeted
)

const (
	SeverityInfo     = core.SeverityInfo
	SeverityLow      = core.SeverityLow
	SeverityMedium   = core.SeverityMedium
	SeverityHigh     = core.SeverityHigh
	SeverityCritical = core.SeverityCritical

	LevelPassive    = core.LevelPassive
	LevelDefault    = core.LevelDefault
	LevelAggressive = core.LevelAggressive

	ScopeHost  = core.ScopeHost
	ScopePage  = core.ScopePage
	ScopeParam = core.ScopeParam

	DefaultBudget = core.DefaultBudget
)

var (
	ErrFetchAlreadyFailed = core.ErrFetchAlreadyFailed
	RecordExchange        = core.RecordExchange
	SeverityRank          = core.SeverityRank
	ParseSeverity         = core.ParseSeverity
	ParseLevel            = core.ParseLevel
	MakeDedupeKey         = core.MakeDedupeKey
	MakeKey               = core.MakeKey
	HostScope             = core.HostScope
	BuildEvidence         = core.BuildEvidence
	WithReporter          = core.WithReporter
	Report                = core.Report
	WithLevel             = core.WithLevel
	LevelFrom             = core.LevelFrom
	WithOOB               = core.WithOOB
	OOBFrom               = core.OOBFrom
	WithBrowser           = core.WithBrowser
	BrowserFrom           = core.BrowserFrom
	WithStack             = core.WithStack
	StackFrom             = core.StackFrom
	Filter                = core.Filter
)
