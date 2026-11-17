package desktop

import (
	"testing"

	"github.com/nareyko/denyout/internal/platform"
	"github.com/nareyko/denyout/internal/platform/platformtest"
)

// Public Register/Unregister/Registered must go through the platform.Autostart
// seam; the fake keeps the test from touching real login items.
func TestAutostartForwardersUseInterface(t *testing.T) {
	old := autostart
	t.Cleanup(func() { autostart = old })
	f := &platformtest.FakeAutostart{}
	autostart = f
	if err := RegisterAutostart(); err != nil {
		t.Fatal(err)
	}
	if !AutostartRegistered() || !f.Registered() {
		t.Fatal("not registered via interface")
	}
	if err := UnregisterAutostart(); err != nil {
		t.Fatal(err)
	}
	if AutostartRegistered() {
		t.Fatal("still registered")
	}
}

func TestAutostartContractFake(t *testing.T) {
	platformtest.AutostartContract(t, func() platform.Autostart { return &platformtest.FakeAutostart{} })
}
