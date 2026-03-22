package rules

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"time"
)

// Rule defines a configurable detection rule and enforcement action.
type Rule struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Pattern  string `json:"pattern"`
	Mode     string `json:"mode,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty"`
}

// CompiledRule is a runtime-ready rule with a compiled regex.
type CompiledRule struct {
	ID       string
	Category string
	Severity string
	Action   string
	Mode     string
	Priority int
	Regex    *regexp.Regexp
}

// Manager loads and hot-reloads rule configuration from disk.
type Manager struct {
	path         string
	checkEvery   time.Duration
	logger       *slog.Logger
	mu           sync.RWMutex
	lastCheck    time.Time
	lastModified time.Time
	compiled     []CompiledRule
	actions      map[string]string
}

type fileConfig struct {
	Rules []Rule `json:"rules"`
}

// NewManager creates a rule manager with built-in defaults and optional file overrides.
func NewManager(path string, checkEvery time.Duration, logger *slog.Logger) (*Manager, error) {
	manager := &Manager{
		path:       path,
		checkEvery: checkEvery,
		logger:     logger,
		actions:    make(map[string]string),
	}
	if err := manager.reload(true); err != nil {
		return nil, err
	}
	return manager, nil
}

// Rules returns the currently active compiled rules.
func (m *Manager) Rules() []CompiledRule {
	_ = m.reload(false)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]CompiledRule(nil), m.compiled...)
}

// ActionFor returns the configured action for a rule identifier.
func (m *Manager) ActionFor(ruleID string) string {
	_ = m.reload(false)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.actions[ruleID]
}

func (m *Manager) reload(force bool) error {
	if m.path == "" && !force {
		return nil
	}
	if !force && time.Since(m.lastCheck) < m.checkEvery {
		return nil
	}
	m.lastCheck = time.Now()

	rules := DefaultRules()
	modified := time.Time{}
	if m.path != "" {
		info, err := os.Stat(m.path)
		if err != nil {
			return fmt.Errorf("stat policy file: %w", err)
		}
		modified = info.ModTime()
		if !force && !modified.After(m.lastModified) {
			return nil
		}

		payload, err := os.ReadFile(m.path)
		if err != nil {
			return fmt.Errorf("read policy file: %w", err)
		}
		var cfg fileConfig
		if err := json.Unmarshal(payload, &cfg); err != nil {
			return fmt.Errorf("decode policy file: %w", err)
		}
		rules = mergeRules(rules, cfg.Rules)
	}

	compiled := make([]CompiledRule, 0, len(rules))
	actions := make(map[string]string, len(rules))
	for _, rule := range rules {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("compile rule %s: %w", rule.ID, err)
		}
		compiled = append(compiled, CompiledRule{ID: rule.ID, Category: rule.Category, Severity: rule.Severity, Action: rule.Action, Mode: defaultMode(rule.Mode), Priority: rule.Priority, Regex: re})
		actions[rule.ID] = rule.Action
	}

	m.mu.Lock()
	m.compiled = compiled
	m.actions = actions
	m.lastModified = modified
	m.mu.Unlock()

	if m.logger != nil {
		m.logger.Info("rules_reloaded", "count", len(compiled), "path", m.path)
	}
	return nil
}

func mergeRules(base, overrides []Rule) []Rule {
	byID := make(map[string]Rule, len(base)+len(overrides))
	for _, rule := range base {
		byID[rule.ID] = rule
	}
	for _, override := range overrides {
		existing, ok := byID[override.ID]
		if ok {
			if override.Category != "" {
				existing.Category = override.Category
			}
			if override.Severity != "" {
				existing.Severity = override.Severity
			}
			if override.Action != "" {
				existing.Action = override.Action
			}
			if override.Pattern != "" {
				existing.Pattern = override.Pattern
			}
			if override.Mode != "" {
				existing.Mode = override.Mode
			}
			if override.Priority != 0 {
				existing.Priority = override.Priority
			}
			if override.Enabled != nil {
				existing.Enabled = override.Enabled
			}
			byID[override.ID] = existing
			continue
		}
		byID[override.ID] = override
	}
	merged := make([]Rule, 0, len(byID))
	for _, rule := range byID {
		merged = append(merged, rule)
	}
	return merged
}

func defaultMode(mode string) string {
	if mode == "" {
		return "raw"
	}
	return mode
}
