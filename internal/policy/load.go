package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// schemaFS is set by load_schema.go via go:embed of schemas/denyout-config.v1.json.
// LoadFile validates YAML against that schema (fail closed).

// LoadFile reads and validates a denyout/v1 YAML config.
func LoadFile(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadBytes(raw)
}

// LoadBytes validates and parses config YAML bytes.
func LoadBytes(raw []byte) (*Config, error) {
	if err := validateSchema(raw); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(false)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if cfg.APIVersion != "denyout/v1" {
		return nil, fmt.Errorf("apiVersion must be denyout/v1")
	}
	if cfg.Kind != "Config" {
		return nil, fmt.Errorf("kind must be Config")
	}
	if cfg.Mode == "" {
		cfg.Mode = "enforce"
	}
	if err := validateCustomRegex(&cfg); err != nil {
		return nil, err
	}
	if err := mergePreset(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateCustomRegex(cfg *Config) error {
	for _, cr := range cfg.Scanners.CustomRegex {
		if cr.Pattern == "" {
			return fmt.Errorf("custom_regex %q: empty pattern", cr.ID)
		}
		if _, err := regexp.Compile(cr.Pattern); err != nil {
			return fmt.Errorf("custom_regex %q: invalid pattern: %w", cr.ID, err)
		}
	}
	return nil
}

func validateSchema(yamlRaw []byte) error {
	var doc any
	if err := yaml.Unmarshal(yamlRaw, &doc); err != nil {
		return fmt.Errorf("yaml parse: %w", err)
	}
	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var jsonDoc any
	if err := json.Unmarshal(jsonBytes, &jsonDoc); err != nil {
		return err
	}

	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("https://denyout.com/schemas/denyout-config.v1.json", strings.NewReader(schemaJSON)); err != nil {
		return err
	}
	sch, err := compiler.Compile("https://denyout.com/schemas/denyout-config.v1.json")
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	if err := sch.Validate(jsonDoc); err != nil {
		return err
	}
	return nil
}

// DefaultEnforceModels returns a built-in enforce+models config for `denyout check` without --config.
func DefaultEnforceModels() (*Config, error) {
	path, err := findPresetOrExample()
	if err == nil {
		return LoadFile(path)
	}
	// Fallback embedded-minimal when examples are not on disk (tests may set via LoadBytes).
	minimal := []byte(`
apiVersion: denyout/v1
kind: Config
mode: enforce
preset: models
scanners:
  min_value_len: 6
  named_query:
    enabled: true
  canaries:
    - "DENYOUT_CANARY_"
    - "ARVISER_CANARY_"
`)
	return LoadBytes(minimal)
}

func findPresetOrExample() (string, error) {
	candidates := []string{
		"examples/policies/denyout.enforce.models.yaml",
		filepath.Join("..", "examples", "policies", "denyout.enforce.models.yaml"),
		filepath.Join("..", "..", "examples", "policies", "denyout.enforce.models.yaml"),
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "examples", "policies", "denyout.enforce.models.yaml"),
		)
		// Walk up a few levels from cwd (e.g. running from repo root or cmd/).
		dir := wd
		for i := 0; i < 4; i++ {
			candidates = append(candidates, filepath.Join(dir, "examples", "policies", "denyout.enforce.models.yaml"))
			dir = filepath.Dir(dir)
		}
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("example policy not found")
}

func mergePreset(cfg *Config) error {
	if cfg.Preset == "" || cfg.Preset == "none" {
		return nil
	}
	hosts, err := loadPresetHosts(cfg.Preset)
	if err != nil {
		return err
	}
	existing := map[string]struct{}{}
	for _, r := range cfg.Allow {
		existing[strings.ToLower(r.Host)] = struct{}{}
	}
	for _, h := range hosts {
		key := strings.ToLower(h)
		if _, ok := existing[key]; ok {
			continue
		}
		cfg.Allow = append(cfg.Allow, Rule{Host: h, Reason: "preset:" + cfg.Preset})
		existing[key] = struct{}{}
	}
	return nil
}

func loadPresetHosts(name string) ([]string, error) {
	if name != "models" && name != "models+pkg" && name != "strict" && name != "dev" {
		return nil, fmt.Errorf("unknown preset %q", name)
	}
	// models / models+pkg / strict / dev — for stub, models hosts are enough; others extend later.
	path, err := findPresetFile("models.yaml")
	if err != nil {
		// Built-in fallback so schema-valid minimal configs still work in tests.
		return defaultModelsHosts(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Hosts []string `yaml:"hosts"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Hosts) == 0 {
		return defaultModelsHosts(), nil
	}
	return doc.Hosts, nil
}

func findPresetFile(name string) (string, error) {
	candidates := []string{
		filepath.Join("presets", name),
	}
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for i := 0; i < 4; i++ {
			candidates = append(candidates, filepath.Join(dir, "presets", name))
			dir = filepath.Dir(dir)
		}
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("preset file not found")
}

func defaultModelsHosts() []string {
	return []string{
		"api.anthropic.com",
		"api.openai.com",
		"api.groq.com",
		"api.mistral.ai",
		"generativelanguage.googleapis.com",
		"api.cohere.ai",
		"api.together.xyz",
		"api.fireworks.ai",
	}
}
