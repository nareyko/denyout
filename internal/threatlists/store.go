package threatlists

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FeedStatus is persisted per-subscription health (Settings surface).
type FeedStatus struct {
	ID          string    `json:"id"`
	Enabled     bool      `json:"enabled"`
	Active      bool      `json:"active"` // ready for policy (URLhaus after first OK)
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	EntryCount  int       `json:"entry_count"`
	Bytes       int       `json:"bytes"`
	Category    Category  `json:"category"`
	Format      Format    `json:"format"`
}

// StatusFile is the on-disk status snapshot.
type StatusFile struct {
	PollHours int                   `json:"poll_hours"`
	Feeds     map[string]FeedStatus `json:"feeds"`
}

// Store manages cached list files + status under Dir.
type Store struct {
	Dir string

	mu     sync.RWMutex
	status StatusFile
	sets   map[string]map[string]struct{} // id → hosts
}

// Open creates/loads a Store at dir (mkdir as needed).
func Open(dir string) (*Store, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(filepath.Join(dir, "feeds"), 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		Dir:  dir,
		sets: make(map[string]map[string]struct{}),
		status: StatusFile{
			PollHours: DefaultPollHours,
			Feeds:     make(map[string]FeedStatus),
		},
	}
	if err := s.loadStatus(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if s.status.Feeds == nil {
		s.status.Feeds = make(map[string]FeedStatus)
	}
	s.status.PollHours = ClampPollHours(s.status.PollHours)
	if err := s.loadCachedFeeds(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) statusPath() string {
	return filepath.Join(s.Dir, "status.json")
}

func (s *Store) feedPath(id string) string {
	return filepath.Join(s.Dir, "feeds", id+".txt")
}

func (s *Store) loadStatus() error {
	raw, err := os.ReadFile(s.statusPath())
	if err != nil {
		return err
	}
	var st StatusFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("threatlists status: %w", err)
	}
	s.status = st
	return nil
}

func (s *Store) saveStatusLocked() error {
	raw, err := json.MarshalIndent(s.status, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statusPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.statusPath())
}

func (s *Store) loadCachedFeeds() error {
	for id, st := range s.status.Feeds {
		raw, err := os.ReadFile(s.feedPath(id))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		format := st.Format
		if format == "" {
			if sub, ok := CatalogByID(id); ok {
				format = sub.Format
			} else {
				format = FormatDomains
			}
		}
		s.sets[id] = Parse(raw, format)
	}
	return nil
}

// Status returns a copy of persisted feed health.
func (s *Store) Status() StatusFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := StatusFile{
		PollHours: s.status.PollHours,
		Feeds:     make(map[string]FeedStatus, len(s.status.Feeds)),
	}
	for k, v := range s.status.Feeds {
		out.Feeds[k] = v
	}
	return out
}

// SetPollHours updates the global poll interval and persists.
func (s *Store) SetPollHours(h int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.PollHours = ClampPollHours(h)
	return s.saveStatusLocked()
}

// SetEnabled toggles a feed and persists (does not fetch).
func (s *Store) SetEnabled(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status.Feeds[id]
	st.ID = id
	st.Enabled = enabled
	if sub, ok := CatalogByID(id); ok {
		st.Category = sub.Category
		st.Format = sub.Format
	}
	if !enabled {
		st.Active = false
	} else if st.EntryCount > 0 && !st.LastSuccess.IsZero() {
		st.Active = true
	} else {
		st.Active = false // wait for successful fetch (esp. ActiveAfterFirstOK)
	}
	s.status.Feeds[id] = st
	return s.saveStatusLocked()
}

// EnsureCatalogDefaults seeds status rows for core + advanced catalogs without fetching.
func (s *Store) EnsureCatalogDefaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range append(CoreCatalog(), AdvancedCatalog()...) {
		if _, ok := s.status.Feeds[sub.ID]; ok {
			continue
		}
		s.status.Feeds[sub.ID] = FeedStatus{
			ID:       sub.ID,
			Enabled:  sub.Enabled,
			Category: sub.Category,
			Format:   sub.Format,
		}
	}
	return s.saveStatusLocked()
}

// CheckThreat implements policy.ThreatChecker (any active category).
func (s *Store) CheckThreat(host string) (feedID string, hit bool) {
	return s.Contains(host, "")
}

// Contains reports whether host matches an active+enabled feed in category
// (empty category = any). Exact host only for L1; wildcard later if needed.
func (s *Store) Contains(host string, category Category) (feedID string, ok bool) {
	host = normalizeHost(host)
	if host == "" {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, set := range s.sets {
		st := s.status.Feeds[id]
		if !st.Enabled || !st.Active {
			continue
		}
		if category != "" && st.Category != category {
			continue
		}
		if _, hit := set[host]; hit {
			return id, true
		}
	}
	return "", false
}

// EntryCount returns cached hosts for id (0 if missing).
func (s *Store) EntryCount(id string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sets[id])
}

// AllEnabledStale reports whether every enabled feed is older than maxAge
// (or never succeeded). Used for Problems / needs attention.
func (s *Store) AllEnabledStale(now time.Time, maxAge time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	any := false
	for _, st := range s.status.Feeds {
		if !st.Enabled {
			continue
		}
		any = true
		if st.LastSuccess.IsZero() || now.Sub(st.LastSuccess) > maxAge {
			continue
		}
		return false
	}
	return any
}

// atomicWriteFeed writes raw bytes then renames into place.
func (s *Store) atomicWriteFeed(id string, raw []byte) error {
	path := s.feedPath(id)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
