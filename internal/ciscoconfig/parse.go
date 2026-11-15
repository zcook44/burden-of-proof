// Package ciscoconfig reads a saved Cisco running configuration and optional
// port-role table. It does not connect to a device. Banner bodies and macro
// bodies are not treated as commands, because those lines are not part of the
// active configuration.
package ciscoconfig

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Config is a column-oriented view of one running-config snapshot.
type Config struct {
	Hostname    string
	HasEnd      bool
	HasVersion  bool
	Globals     map[string]bool
	Blocks      []*Block
	Uncertain   bool
	Uncertainty string
}

// Block is one column-0 command and the indented lines that belong to it.
type Block struct {
	Header string
	Set    map[string]bool
	Lines  []string
}

// Parse splits a running-config into globals and indented blocks.
// An ambiguous banner, macro, or indentation mark is recorded on Uncertain
// and must not produce a pass or an open finding.
func Parse(data []byte) (*Config, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("empty Cisco configuration")
	}
	cfg := &Config{Globals: map[string]bool{}}
	var current *Block
	banner := ""
	macro := false
	for _, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if banner != "" {
			if strings.Contains(raw, banner) {
				banner = ""
			}
			continue
		}
		if macro {
			if strings.TrimSpace(raw) == "@" {
				macro = false
			}
			continue
		}
		if strings.TrimSpace(raw) == "" {
			continue
		}
		trimmedLeft := strings.TrimLeft(raw, " \t")
		if strings.HasPrefix(trimmedLeft, "!") {
			if trimmedLeft == raw {
				current = nil
			}
			continue
		}
		if raw != strings.TrimSpace(raw) {
			if current == nil {
				cfg.Uncertain = true
				cfg.Uncertainty = "indented command outside a configuration block"
				return cfg, nil
			}
			line := strings.TrimSpace(raw)
			current.Lines = append(current.Lines, line)
			current.Set[line] = true
			continue
		}
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "banner ") {
			delim, closed, ok := bannerDelimiter(line)
			if !ok {
				cfg.Uncertain = true
				cfg.Uncertainty = "banner delimiter could not be determined"
				return cfg, nil
			}
			current = nil
			if !closed {
				banner = delim
			}
			continue
		}
		if strings.HasPrefix(line, "macro name ") {
			current = nil
			macro = true
			continue
		}
		if strings.HasPrefix(line, "Building configuration") || strings.HasPrefix(line, "Current configuration") {
			continue
		}
		if line == "end" {
			current = nil
			cfg.HasEnd = true
			continue
		}
		if name, ok := strings.CutPrefix(line, "hostname "); ok {
			if cfg.Hostname != "" && cfg.Hostname != name {
				cfg.Uncertain = true
				cfg.Uncertainty = "configuration contains conflicting hostname commands"
				return cfg, nil
			}
			cfg.Hostname = name
		}
		if strings.HasPrefix(line, "version ") {
			cfg.HasVersion = true
		}
		cfg.Globals[line] = true
		current = &Block{Header: line, Set: map[string]bool{}}
		cfg.Blocks = append(cfg.Blocks, current)
	}
	if banner != "" || macro {
		cfg.Uncertain = true
		cfg.Uncertainty = "banner or macro was not closed"
	}
	return cfg, nil
}

// bannerDelimiter reads the delimiter from the text after the banner type.
// Searching the whole line is wrong: the letter d in "motd" is not the delimiter
// of "banner motd d".
func bannerDelimiter(line string) (delim string, closed, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "banner" {
		return "", false, false
	}
	typeAt := strings.Index(line, fields[1])
	if typeAt < 0 {
		return "", false, false
	}
	after := strings.TrimLeft(line[typeAt+len(fields[1]):], " \t")
	delim = fields[2]
	if delim == "" || !strings.HasPrefix(after, delim) {
		return "", false, false
	}
	rest := after[len(delim):]
	return delim, strings.Contains(rest, delim), true
}

// Family is the command dialect implied by an official benchmark ID.
func Family(benchmarkID string) string {
	if strings.Contains(benchmarkID, "NX-OS") || strings.Contains(benchmarkID, "NXOS") {
		return "nxos"
	}
	return "ios"
}

// Complete reports whether absence of a command is meaningful.
// IOS running-config ends with "end". NX-OS snapshots in this workflow are
// complete when they carry a version line and a hostname.
func (c *Config) Complete(family string) bool {
	if c == nil || c.Uncertain || c.Hostname == "" {
		return false
	}
	if family == "nxos" {
		return c.HasVersion
	}
	return c.HasEnd && c.HasVersion
}

func (c *Config) Has(line string) bool {
	return c != nil && c.Globals[line]
}

func (c *Config) HasPrefix(prefix string) bool {
	if c == nil {
		return false
	}
	if c.Globals[prefix] {
		return true
	}
	for line := range c.Globals {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func (c *Config) CountPrefix(prefix string) int {
	if c == nil {
		return 0
	}
	n := 0
	for line := range c.Globals {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}

func (c *Config) Interface(name string) *Block {
	for _, block := range c.Blocks {
		if block.InterfaceName() == name {
			return block
		}
	}
	return nil
}

func (c *Config) Switchports() []*Block {
	var out []*Block
	for _, block := range c.Blocks {
		name := block.InterfaceName()
		if name != "" && isSwitchport(name) {
			out = append(out, block)
		}
	}
	return out
}

func (b *Block) InterfaceName() string {
	name, ok := strings.CutPrefix(b.Header, "interface ")
	if !ok || name == "" || strings.Contains(name, " ") {
		return ""
	}
	return name
}

func (b *Block) Has(line string) bool { return b != nil && b.Set[line] }

func (b *Block) HasPrefix(prefix string) bool {
	if b == nil {
		return false
	}
	for line := range b.Set {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func (b *Block) FirstPrefix(prefix string) string {
	for _, line := range b.Lines {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func isSwitchport(name string) bool {
	for _, prefix := range []string{
		"Ethernet", "FastEthernet", "GigabitEthernet", "TwoGigabitEthernet",
		"FiveGigabitEthernet", "TenGigabitEthernet", "TwentyFiveGigE",
		"FortyGigabitEthernet", "HundredGigE", "AppGigabitEthernet",
		"Port-channel", "port-channel",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func (c *Config) anyBlockHas(line string) bool {
	for _, block := range c.Blocks {
		if block.Has(line) {
			return true
		}
	}
	return false
}

func (c *Config) anyBlockPrefix(prefix string) bool {
	for _, block := range c.Blocks {
		if block.HasPrefix(prefix) {
			return true
		}
	}
	return false
}

// ParseVLANs reads an IOS VLAN list such as "20" or "2,4-8,11".
// Forms that add, remove, or exclude VLANs are rejected so the caller
// leaves the control unreviewed.
func ParseVLANs(spec string) (map[int]bool, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.Contains(spec, " ") {
		return nil, false
	}
	lower := strings.ToLower(spec)
	if strings.Contains(lower, "except") || strings.Contains(lower, "add") || strings.Contains(lower, "remove") || lower == "all" || lower == "none" {
		return nil, false
	}
	out := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, false
			}
			start, err1 := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || start < 1 || end > 4094 || end < start || end-start > 4094 {
				return nil, false
			}
			for n := start; n <= end; n++ {
				out[n] = true
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 4094 {
			return nil, false
		}
		out[n] = true
	}
	return out, true
}

func vlanCommandSet(cfg *Config, prefix string) (map[int]bool, bool) {
	combined := map[int]bool{}
	found := false
	for line := range cfg.Globals {
		spec, ok := strings.CutPrefix(line, prefix)
		if !ok {
			continue
		}
		set, ok := ParseVLANs(spec)
		if !ok {
			return nil, false
		}
		found = true
		for n := range set {
			combined[n] = true
		}
	}
	return combined, found
}
