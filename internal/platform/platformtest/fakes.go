package platformtest

import (
	"errors"
	"os"
	"runtime"
	"sync"

	"github.com/nareyko/denyout/internal/platform"
)

// FakeRedirector is an in-memory platform.Redirector.
type FakeRedirector[S any] struct {
	mu     sync.Mutex
	active bool
	Fail   error // returned by Apply when set
	Calls  []string
}

func (f *FakeRedirector[S]) Apply(S) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "apply")
	if f.Fail != nil {
		return f.Fail
	}
	f.active = true
	return nil
}

func (f *FakeRedirector[S]) Remove(S) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "remove")
	f.active = false
	return nil
}

func (f *FakeRedirector[S]) Status() platform.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return platform.Status{Active: f.active, Platform: runtime.GOOS, Detail: "fake"}
}

// FakeTrustStore is an in-memory platform.TrustStore.
type FakeTrustStore struct {
	mu        sync.Mutex
	installed bool
	Fail      error // returned by Install when set
	Calls     []string
}

func (f *FakeTrustStore) Install(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "install")
	if f.Fail != nil {
		return f.Fail
	}
	if path == "" {
		return errors.New("empty CA path")
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	f.installed = true
	return nil
}

func (f *FakeTrustStore) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "remove")
	f.installed = false
	return nil
}

func (f *FakeTrustStore) Installed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installed
}

// FakeAutostart is an in-memory platform.Autostart.
type FakeAutostart struct {
	mu  sync.Mutex
	reg bool
}

func (f *FakeAutostart) Register(string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reg = true
	return nil
}

func (f *FakeAutostart) Unregister() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reg = false
	return nil
}

func (f *FakeAutostart) Registered() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reg
}
