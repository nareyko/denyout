package desktop

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/threatlists"
)

// ThreatFeedView is one subscription row for Settings.
type ThreatFeedView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	Enabled     bool   `json:"enabled"`
	Active      bool   `json:"active"`
	EntryCount  int    `json:"entry_count"`
	LastSuccess string `json:"last_success,omitempty"` // RFC3339 or empty
	LastError   string `json:"last_error,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	Advanced    bool   `json:"advanced,omitempty"` // OISD / StevenBlack - not core job
}

// ThreatListsView is Settings -> Threat lists payload.
type ThreatListsView struct {
	Available             bool             `json:"available"`
	PollHours             int              `json:"poll_hours"`
	BlockPhishing         bool             `json:"block_phishing"`
	BlockMalware          bool             `json:"block_malware"`
	BlockStronger         bool             `json:"block_stronger"` // HaGeZi TIF medium
	BlockAdsTrackers      bool             `json:"block_ads_trackers"`
	NeedsAttention        bool             `json:"needs_attention"`
	Feeds                 []ThreatFeedView `json:"feeds"`
	AdvancedFeeds         []ThreatFeedView `json:"advanced_feeds"`
	AboutNote             string           `json:"about_note"`
	StrongerWarning       string           `json:"stronger_warning"`
	AdvancedWarning       string           `json:"advanced_warning"`
	AggressiveAdsWarning  string           `json:"aggressive_ads_warning"`
	AdsTrackersWarning    string           `json:"ads_trackers_warning"`
	ProductExceptions     int              `json:"product_exceptions"`
	ProductExceptionHosts []string         `json:"product_exception_hosts"`
	ProductExceptionsNote string           `json:"product_exceptions_note"`
}

// StrongerFirstEnableWarning is shown once in UI before enabling HaGeZi medium.
const StrongerFirstEnableWarning = "Stronger adds a large extra malware/threat list (HaGeZi TIF medium). It may block more sites and use more disk/memory. If something breaks, use Allow this site. Continue?"

// AdvancedFeedEnableWarning is shown before enabling a gentle ads feed (OISD small).
const AdvancedFeedEnableWarning = "Ads and tracker lists are optional privacy filters - not DenyOut's core job (use Pi-hole or similar for network-wide ads). They may break sites. Continue?"

// AggressiveAdsFeedWarning is shown before enabling OISD big or StevenBlack.
const AggressiveAdsFeedWarning = "This list is broader and more aggressive than OISD small. It may break logins, CDNs, or analytics that sites need. Prefer OISD small first. Continue?"

// AdsTrackersMasterWarning is shown when turning on Block ads & trackers.
const AdsTrackersMasterWarning = "Block ads and trackers uses optional lists (OISD / StevenBlack). This is not DenyOut's core phishing/malware job and may break some sites. Continue?"

// GetThreatLists returns Book C status for Settings (opens store if needed; no force refresh).
func (a *App) GetThreatLists() ThreatListsView {
	st := a.ensureThreatStore(false)
	unbreak := policy.DefaultUnbreakHosts()
	out := ThreatListsView{
		PollHours:             threatlists.DefaultPollHours,
		AboutNote:             "DenyOut downloads known phishing and malware domain lists by default. Ads and trackers lists are optional (off). Lists stay on this computer. Failed downloads keep the last good copy - Protect still works.",
		StrongerWarning:       StrongerFirstEnableWarning,
		AdvancedWarning:       AdvancedFeedEnableWarning,
		AggressiveAdsWarning:  AggressiveAdsFeedWarning,
		AdsTrackersWarning:    AdsTrackersMasterWarning,
		Feeds:                 []ThreatFeedView{},
		AdvancedFeeds:         []ThreatFeedView{},
		ProductExceptions:     len(unbreak),
		ProductExceptionHosts: unbreak,
		ProductExceptionsNote: "Product exceptions are maintained by DenyOut so threat lists do not break common OS, login, and update hosts. Read-only. Secrets scanners still apply.",
	}
	if st == nil {
		return out
	}
	out.Available = true
	_ = st.EnsureCatalogDefaults()
	status := st.Status()
	out.PollHours = status.PollHours
	out.NeedsAttention = (&threatlists.Updater{Store: st}).NeedsAttention()

	for _, sub := range threatlists.CoreCatalog() {
		row := feedViewFrom(sub, status, false)
		out.Feeds = append(out.Feeds, row)
		switch sub.ID {
		case threatlists.IDPhishingArmy:
			out.BlockPhishing = row.Enabled
		case threatlists.IDURLHaus:
			out.BlockMalware = row.Enabled
		case threatlists.IDHageziTIFMedium:
			out.BlockStronger = row.Enabled
		}
	}
	for _, sub := range threatlists.AdvancedCatalog() {
		row := feedViewFrom(sub, status, true)
		out.AdvancedFeeds = append(out.AdvancedFeeds, row)
		if row.Enabled {
			out.BlockAdsTrackers = true
		}
	}
	return out
}

func feedViewFrom(sub threatlists.Subscription, status threatlists.StatusFile, advanced bool) ThreatFeedView {
	fs := status.Feeds[sub.ID]
	enabled := sub.Enabled
	if _, ok := status.Feeds[sub.ID]; ok {
		enabled = fs.Enabled
	}
	row := ThreatFeedView{
		ID:         sub.ID,
		Label:      threatFeedLabel(sub.ID),
		Category:   string(sub.Category),
		Enabled:    enabled,
		Active:     fs.Active,
		EntryCount: fs.EntryCount,
		LastError:  fs.LastError,
		Homepage:   sub.Homepage,
		Advanced:   advanced,
	}
	if !fs.LastSuccess.IsZero() {
		row.LastSuccess = fs.LastSuccess.UTC().Format(time.RFC3339)
	}
	return row
}

func threatFeedLabel(id string) string {
	switch id {
	case threatlists.IDPhishingArmy:
		return "Phishing Army"
	case threatlists.IDURLHaus:
		return "URLhaus filter (malware)"
	case threatlists.IDHageziTIFMedium:
		return "Stronger threat list"
	case threatlists.IDOISDSmall:
		return "OISD small (ads/trackers)"
	case threatlists.IDOISDBig:
		return "OISD big (aggressive)"
	case threatlists.IDStevenBlack:
		return "StevenBlack hosts"
	default:
		return id
	}
}

// UISetBlockPhishing enables/disables the phishing feed.
func (a *App) UISetBlockPhishing(on bool) error {
	return a.setThreatFeedEnabled(threatlists.IDPhishingArmy, on)
}

// UISetBlockMalware enables/disables the malware (URLhaus) feed.
// Turning malware off also disables Stronger (nested under malware).
func (a *App) UISetBlockMalware(on bool) error {
	if err := a.setThreatFeedEnabled(threatlists.IDURLHaus, on); err != nil {
		return err
	}
	if !on {
		_ = a.setThreatFeedEnabled(threatlists.IDHageziTIFMedium, false)
	}
	return nil
}

// UISetBlockStronger enables/disables HaGeZi TIF medium (nested under malware).
// Caller must show StrongerFirstEnableWarning on first enable. Requires malware on.
func (a *App) UISetBlockStronger(on bool) error {
	if on {
		st := a.ensureThreatStore(false)
		if st == nil {
			return fmt.Errorf("threat lists unavailable")
		}
		_ = st.EnsureCatalogDefaults()
		mal := st.Status().Feeds[threatlists.IDURLHaus]
		malOn := mal.Enabled
		if _, ok := st.Status().Feeds[threatlists.IDURLHaus]; !ok {
			malOn = true // catalog default
		}
		if !malOn {
			if err := a.setThreatFeedEnabled(threatlists.IDURLHaus, true); err != nil {
				return err
			}
		}
	}
	return a.setThreatFeedEnabled(threatlists.IDHageziTIFMedium, on)
}

// UISetThreatPollHours updates refresh interval (clamped).
func (a *App) UISetThreatPollHours(hours int) error {
	st := a.ensureThreatStore(false)
	if st == nil {
		return fmt.Errorf("threat lists unavailable")
	}
	return st.SetPollHours(hours)
}

// UISetBlockAdsTrackers is the master gate for Advanced ads/tracker feeds.
// OFF disables every AdvancedCatalog feed. ON enables OISD small if none are on yet.
func (a *App) UISetBlockAdsTrackers(on bool) error {
	st := a.ensureThreatStore(false)
	if st == nil {
		return fmt.Errorf("threat lists unavailable")
	}
	_ = st.EnsureCatalogDefaults()
	if !on {
		var last error
		for _, sub := range threatlists.AdvancedCatalog() {
			if err := a.setThreatFeedEnabled(sub.ID, false); err != nil {
				last = err
			}
		}
		return last
	}
	anyOn := false
	status := st.Status()
	for _, sub := range threatlists.AdvancedCatalog() {
		fs := status.Feeds[sub.ID]
		enabled := sub.Enabled
		if _, ok := status.Feeds[sub.ID]; ok {
			enabled = fs.Enabled
		}
		if enabled {
			anyOn = true
			break
		}
	}
	if anyOn {
		a.syncThreatChecker(st)
		return a.rebindThreatsIfProtectOn()
	}
	return a.setThreatFeedEnabled(threatlists.IDOISDSmall, true)
}

// UISetAdvancedThreatFeed enables/disables an Advanced catalog feed (OISD / StevenBlack).
// Caller should show AdvancedFeedEnableWarning before enabling.
// Enabling a feed while the master is off turns ads/trackers on for that feed.
func (a *App) UISetAdvancedThreatFeed(id string, on bool) error {
	id = strings.TrimSpace(id)
	ok := false
	for _, sub := range threatlists.AdvancedCatalog() {
		if sub.ID == id {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("not an advanced feed: %q", id)
	}
	return a.setThreatFeedEnabled(id, on)
}

// UIRefreshThreatLists force-refreshes enabled feeds and rebinds live Protect.
func (a *App) UIRefreshThreatLists() (ThreatListsView, error) {
	st := a.ensureThreatStore(true)
	if st == nil {
		return ThreatListsView{}, fmt.Errorf("threat lists unavailable")
	}
	a.syncThreatChecker(st)
	if err := a.rebindThreatsIfProtectOn(); err != nil {
		return a.GetThreatLists(), err
	}
	return a.GetThreatLists(), nil
}

func (a *App) setThreatFeedEnabled(id string, on bool) error {
	st := a.ensureThreatStore(false)
	if st == nil {
		return fmt.Errorf("threat lists unavailable")
	}
	if err := st.SetEnabled(id, on); err != nil {
		return err
	}
	if on {
		sub, ok := threatlists.CatalogByID(id)
		if !ok {
			return fmt.Errorf("unknown feed %q", id)
		}
		status := st.Status().Feeds[id]
		if status.EntryCount == 0 || !status.Active {
			timeout := 90 * time.Second
			switch id {
			case threatlists.IDHageziTIFMedium, threatlists.IDOISDBig, threatlists.IDStevenBlack:
				timeout = 5 * time.Minute
			case threatlists.IDOISDSmall:
				timeout = 3 * time.Minute
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			u := &threatlists.Updater{Store: st}
			res := u.RefreshOne(ctx, sub)
			if !res.OK && strings.TrimSpace(res.Error) != "" {
				AppendDesktopLog("WARN threatlist enable %s: %s", id, res.Error)
				// Keep enabled; Active stays false until a good fetch.
			}
		}
	}
	a.syncThreatChecker(st)
	return a.rebindThreatsIfProtectOn()
}

func (a *App) syncThreatChecker(st *threatlists.Store) {
	a.mu.Lock()
	sess := a.session
	a.threats = st
	wraps := make([]*wrapProc, 0, len(a.wraps))
	for _, wp := range a.wraps {
		wraps = append(wraps, wp)
	}
	a.mu.Unlock()
	if sess != nil {
		sess.SetThreatChecker(st)
	}
	for _, wp := range wraps {
		if wp != nil && wp.sess != nil {
			wp.sess.SetThreatChecker(st)
		}
	}
}

// rebindThreatsIfProtectOn restarts proxyd so the child process reloads Book C status.
func (a *App) rebindThreatsIfProtectOn() error {
	a.mu.Lock()
	sess := a.session
	wasProxy := a.proxyd != nil
	a.mu.Unlock()
	if sess != nil {
		return nil // in-process store already updated
	}
	if !wasProxy {
		return nil
	}
	_ = a.stopComputerOpts(true, false)
	return a.startComputer()
}
