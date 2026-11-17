package platform_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/platform"
	"github.com/nareyko/denyout/internal/platform/platformtest"
)

func TestFakesSatisfyContracts(t *testing.T) {
	platformtest.RedirectorContract(t, func() platform.Redirector[int] { return &platformtest.FakeRedirector[int]{} }, 1)
	platformtest.TrustStoreContract(t, func() platform.TrustStore { return &platformtest.FakeTrustStore{} })
	platformtest.AutostartContract(t, func() platform.Autostart { return &platformtest.FakeAutostart{} })
}
