// Package cloudsync defines the versioned settings blob synced only when signed in.
package cloudsync

import (
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion is the sync document version.
const SchemaVersion = 1

// Document is the authenticated config payload (GET/PUT /v1/me/config).
type Document struct {
	SchemaVersion int       `json:"schema_version"`
	UpdatedAt     time.Time `json:"updated_at"`
	Settings      Settings  `json:"settings"`
}

// Settings are fields safe to sync across devices.
type Settings struct {
	NotifyLevel            string   `json:"notify_level,omitempty"`
	DecisionTimeoutSec     int      `json:"decision_timeout_sec,omitempty"`
	ReaskIntervalSec       int      `json:"reask_interval_sec,omitempty"`
	AlwaysAllowHosts       []string `json:"always_allow_hosts,omitempty"`
	RememberedKeeps        []string `json:"remembered_keeps,omitempty"`
	RememberedSignalAllows []string `json:"remembered_signal_allows,omitempty"`
	BlockPhishing          *bool    `json:"block_phishing,omitempty"`
	BlockMalware           *bool    `json:"block_malware,omitempty"`
	BlockStronger          *bool    `json:"block_stronger,omitempty"`
	ThreatPollHours        int      `json:"threat_poll_hours,omitempty"`
	SensitiveSinksEnabled  *bool    `json:"sensitive_sinks_enabled,omitempty"`
	SensitiveWritesEnabled *bool    `json:"sensitive_writes_enabled,omitempty"`
	BodyPureA              bool     `json:"body_pure_a,omitempty"`
	AntiChunkEnabled       bool     `json:"anti_chunk_enabled,omitempty"`
	AppliedPackIDs         []string `json:"applied_pack_ids,omitempty"`
}

// NeverSync lists categories that must not appear in the blob (documentation + tests).
var NeverSync = []string{
	"audit_jsonl",
	"raw_urls_with_tokens",
	"canary_values",
	"wrap_command_secrets",
	"file_contents",
	"account_tokens",
}

// Marshal encodes a document.
func Marshal(doc Document) ([]byte, error) {
	if doc.SchemaVersion == 0 {
		doc.SchemaVersion = SchemaVersion
	}
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	return json.Marshal(doc)
}

// Unmarshal decodes and validates schema version.
func Unmarshal(data []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Document{}, err
	}
	if doc.SchemaVersion == 0 {
		doc.SchemaVersion = SchemaVersion
	}
	if doc.SchemaVersion > SchemaVersion {
		return Document{}, fmt.Errorf("unsupported schema_version %d (max %d)", doc.SchemaVersion, SchemaVersion)
	}
	return doc, nil
}

// MergeLWW returns the newer document by UpdatedAt (last-write-wins).
func MergeLWW(local, remote Document) Document {
	if remote.UpdatedAt.After(local.UpdatedAt) {
		return remote
	}
	return local
}
