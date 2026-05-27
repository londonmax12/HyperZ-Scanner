package config

// merge layers overlay's explicitly-set fields on top of the receiver
// in place. Set-ness is determined by:
//   - pointer scalars: overlay's pointer is non-nil
//   - slices: overlay's slice is non-nil (empty wins to allow clearing)
//   - nested *XConfig pointers: recursed when overlay is non-nil
//   - the Settings map: merged at both levels (outer key wins,
//     inner per-check bag keys merge)
//
// merge never frees or replaces the base's nested pointers; it
// allocates new sub-configs only when the base did not have one and
// overlay provides values. The resulting tree is therefore safe to
// hand to the rest of the codebase as if it had been read directly
// from a flat YAML.
func (c *Config) merge(overlay *Config) {
	if overlay == nil {
		return
	}

	if overlay.Timeout != nil {
		c.Timeout = overlay.Timeout
	}
	if overlay.UserAgent != nil {
		c.UserAgent = overlay.UserAgent
	}
	if overlay.Format != nil {
		c.Format = overlay.Format
	}
	if overlay.Mode != nil {
		c.Mode = overlay.Mode
	}
	if overlay.Concurrency != nil {
		c.Concurrency = overlay.Concurrency
	}
	if overlay.CheckConcurrency != nil {
		c.CheckConcurrency = overlay.CheckConcurrency
	}
	if overlay.Rate != nil {
		c.Rate = overlay.Rate
	}
	if overlay.Burst != nil {
		c.Burst = overlay.Burst
	}
	if overlay.MaxRequests != nil {
		c.MaxRequests = overlay.MaxRequests
	}
	if overlay.GlobalRate != nil {
		c.GlobalRate = overlay.GlobalRate
	}
	if overlay.GlobalBurst != nil {
		c.GlobalBurst = overlay.GlobalBurst
	}
	if overlay.MaxRetries != nil {
		c.MaxRetries = overlay.MaxRetries
	}
	if overlay.MaxRetryWait != nil {
		c.MaxRetryWait = overlay.MaxRetryWait
	}
	if overlay.Output != nil {
		c.Output = overlay.Output
	}

	if overlay.LogLevel != nil {
		c.LogLevel = overlay.LogLevel
	}
	if overlay.LogFormat != nil {
		c.LogFormat = overlay.LogFormat
	}

	if overlay.FailOn != nil {
		c.FailOn = overlay.FailOn
	}
	if overlay.CAFile != nil {
		c.CAFile = overlay.CAFile
	}
	if overlay.NoFingerprint != nil {
		c.NoFingerprint = overlay.NoFingerprint
	}

	if overlay.URL != nil {
		c.URL = overlay.URL
	}
	if overlay.URLsFile != nil {
		c.URLsFile = overlay.URLsFile
	}

	c.Crawl = mergeCrawl(c.Crawl, overlay.Crawl)
	c.Scope = mergeScope(c.Scope, overlay.Scope)
	c.Auth = mergeAuth(c.Auth, overlay.Auth)
	c.OOB = mergeOOB(c.OOB, overlay.OOB)
	c.JS = mergeJS(c.JS, overlay.JS)
	c.Proxies = mergeProxies(c.Proxies, overlay.Proxies)
	c.Session = mergeSession(c.Session, overlay.Session)
	c.CSRF = mergeCSRF(c.CSRF, overlay.CSRF)
	c.Baseline = mergeBaseline(c.Baseline, overlay.Baseline)
	c.Checks = mergeChecks(c.Checks, overlay.Checks)
}

func mergeCrawl(base, overlay *CrawlConfig) *CrawlConfig {
	if overlay == nil {
		return base
	}
	out := CrawlConfig{}
	if base != nil {
		out = *base
	}
	if overlay.Enabled != nil {
		out.Enabled = overlay.Enabled
	}
	if overlay.MaxPages != nil {
		out.MaxPages = overlay.MaxPages
	}
	if overlay.Workers != nil {
		out.Workers = overlay.Workers
	}
	if overlay.APIDiscovery != nil {
		out.APIDiscovery = overlay.APIDiscovery
	}
	return &out
}

func mergeScope(base, overlay *ScopeConfig) *ScopeConfig {
	if overlay == nil {
		return base
	}
	out := ScopeConfig{}
	if base != nil {
		out = *base
	}
	if overlay.Hosts != nil {
		out.Hosts = overlay.Hosts
	}
	if overlay.AnyHost != nil {
		out.AnyHost = overlay.AnyHost
	}
	if overlay.Ports != nil {
		out.Ports = overlay.Ports
	}
	if overlay.PathInclude != nil {
		out.PathInclude = overlay.PathInclude
	}
	if overlay.PathExclude != nil {
		out.PathExclude = overlay.PathExclude
	}
	if overlay.MaxDepth != nil {
		out.MaxDepth = overlay.MaxDepth
	}
	return &out
}

func mergeAuth(base, overlay *AuthConfig) *AuthConfig {
	if overlay == nil {
		return base
	}
	out := AuthConfig{}
	if base != nil {
		out = *base
	}
	if overlay.Basic != nil {
		out.Basic = overlay.Basic
	}
	if overlay.Bearer != nil {
		out.Bearer = overlay.Bearer
	}
	if overlay.Headers != nil {
		out.Headers = overlay.Headers
	}
	if overlay.Cookies != nil {
		out.Cookies = overlay.Cookies
	}
	if overlay.CookiesFile != nil {
		out.CookiesFile = overlay.CookiesFile
	}
	return &out
}

func mergeOOB(base, overlay *OOBConfig) *OOBConfig {
	if overlay == nil {
		return base
	}
	out := OOBConfig{}
	if base != nil {
		out = *base
	}
	if overlay.Enabled != nil {
		out.Enabled = overlay.Enabled
	}
	if overlay.Listen != nil {
		out.Listen = overlay.Listen
	}
	if overlay.Host != nil {
		out.Host = overlay.Host
	}
	if overlay.Wait != nil {
		out.Wait = overlay.Wait
	}
	return &out
}

func mergeJS(base, overlay *JSConfig) *JSConfig {
	if overlay == nil {
		return base
	}
	out := JSConfig{}
	if base != nil {
		out = *base
	}
	if overlay.Enabled != nil {
		out.Enabled = overlay.Enabled
	}
	if overlay.Concurrent != nil {
		out.Concurrent = overlay.Concurrent
	}
	return &out
}

func mergeProxies(base, overlay *ProxiesConfig) *ProxiesConfig {
	if overlay == nil {
		return base
	}
	out := ProxiesConfig{}
	if base != nil {
		out = *base
	}
	if overlay.URLs != nil {
		out.URLs = overlay.URLs
	}
	if overlay.File != nil {
		out.File = overlay.File
	}
	if overlay.Scrape != nil {
		out.Scrape = overlay.Scrape
	}
	if overlay.Sources != nil {
		out.Sources = overlay.Sources
	}
	if overlay.StatsTop != nil {
		out.StatsTop = overlay.StatsTop
	}
	return &out
}

func mergeSession(base, overlay *SessionConfig) *SessionConfig {
	if overlay == nil {
		return base
	}
	out := SessionConfig{}
	if base != nil {
		out = *base
	}
	if overlay.CheckURL != nil {
		out.CheckURL = overlay.CheckURL
	}
	if overlay.Pattern != nil {
		out.Pattern = overlay.Pattern
	}
	if overlay.Every != nil {
		out.Every = overlay.Every
	}
	return &out
}

func mergeCSRF(base, overlay *CSRFConfig) *CSRFConfig {
	if overlay == nil {
		return base
	}
	out := CSRFConfig{}
	if base != nil {
		out = *base
	}
	if overlay.TokenSource != nil {
		out.TokenSource = overlay.TokenSource
	}
	if overlay.Inject != nil {
		out.Inject = overlay.Inject
	}
	if overlay.Header != nil {
		out.Header = overlay.Header
	}
	if overlay.Param != nil {
		out.Param = overlay.Param
	}
	return &out
}

func mergeBaseline(base, overlay *BaselineConfig) *BaselineConfig {
	if overlay == nil {
		return base
	}
	out := BaselineConfig{}
	if base != nil {
		out = *base
	}
	if overlay.Path != nil {
		out.Path = overlay.Path
	}
	if overlay.Format != nil {
		out.Format = overlay.Format
	}
	return &out
}

// mergeChecks merges the catalog-control block. Enable / Disable lists
// follow the slice convention (overlay non-nil replaces); Settings is
// merged at both levels so a profile that tweaks one key for one check
// does not have to re-state every other check's bag.
func mergeChecks(base, overlay *ChecksConfig) *ChecksConfig {
	if overlay == nil {
		return base
	}
	out := ChecksConfig{}
	if base != nil {
		out = *base
	}
	if overlay.Enable != nil {
		out.Enable = overlay.Enable
	}
	if overlay.Disable != nil {
		out.Disable = overlay.Disable
	}
	if overlay.Pollute != nil {
		out.Pollute = overlay.Pollute
	}
	if overlay.Settings != nil {
		if out.Settings == nil {
			out.Settings = map[string]map[string]interface{}{}
		} else {
			// Copy so the merge does not mutate the base map shared
			// with the caller's File value.
			copied := make(map[string]map[string]interface{}, len(out.Settings))
			for k, v := range out.Settings {
				copied[k] = v
			}
			out.Settings = copied
		}
		for check, bag := range overlay.Settings {
			existing := out.Settings[check]
			if existing == nil {
				out.Settings[check] = bag
				continue
			}
			merged := make(map[string]interface{}, len(existing)+len(bag))
			for k, v := range existing {
				merged[k] = v
			}
			for k, v := range bag {
				merged[k] = v
			}
			out.Settings[check] = merged
		}
	}
	return &out
}
