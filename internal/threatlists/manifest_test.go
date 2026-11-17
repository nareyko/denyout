package threatlists

import "testing"

func TestNormalizeCategoryAdsTrackersAlias(t *testing.T) {
	if NormalizeCategory(CategoryTelemetry) != CategoryAdsTrackers {
		t.Fatalf("telemetry alias: got %q", NormalizeCategory(CategoryTelemetry))
	}
	if !IsAdsTrackers(CategoryTelemetry) || !IsAdsTrackers(CategoryAdsTrackers) {
		t.Fatal("IsAdsTrackers")
	}
	if NormalizeCategory(CategoryPhishing) != CategoryPhishing {
		t.Fatal("phishing must stay")
	}
}

func TestAdvancedCatalogAdsTrackers(t *testing.T) {
	for _, sub := range AdvancedCatalog() {
		if sub.Category != CategoryAdsTrackers {
			t.Fatalf("%s category=%q want ads_trackers", sub.ID, sub.Category)
		}
		if sub.Enabled {
			t.Fatalf("%s must default off", sub.ID)
		}
	}
}
