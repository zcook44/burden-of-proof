// Package netxccdf writes and reads an OpenSCAP-style XCCDF 1.2 result for a
// network STIG scan. It is scan evidence, not an official DISA benchmark.
package netxccdf

import (
	"encoding/xml"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const xmlns = "http://checklists.nist.gov/xccdf/1.2"

// Item is one oscap-style rule-result.
type Item struct {
	RuleID   string
	Severity string
	Result   string
	Message  string
}

// Identity is the device record copied onto the checklist target page.
// HostName is the short name used in the running configuration and in file names.
type Identity struct {
	HostName       string
	FQDN           string
	IPAddress      string
	MACAddress     string
	Role           string
	TargetType     string
	TechnologyArea string
}

// ResultMeta is the evidence bound into a scan result beside the rule statuses.
type ResultMeta struct {
	ConfigSHA256    string
	ConfigComplete  bool
	TailoringSHA256 string
}

// Scan is the TestResult a collector hands to checklist conversion.
type Scan struct {
	Host            string
	BenchmarkID     string
	ConfigSHA256    string
	ConfigComplete  bool
	TailoringSHA256 string
	Identity        Identity
	Rules           map[string]Item
}

type document struct {
	XMLName xml.Name `xml:"Benchmark"`
	XMLNS   string   `xml:"xmlns,attr"`
	ID      string   `xml:"id,attr"`
	Title   string   `xml:"title"`
	Version string   `xml:"version"`
	Test    result   `xml:"TestResult"`
}

type result struct {
	ID      string  `xml:"id,attr"`
	Start   string  `xml:"start-time,attr"`
	End     string  `xml:"end-time,attr"`
	Target  string  `xml:"target"`
	Address string  `xml:"target-address"`
	Facts   facts   `xml:"target-facts"`
	Profile profile `xml:"profile"`
	Rules   []rule  `xml:"rule-result"`
}

type profile struct {
	IDRef string `xml:"idref,attr"`
}

type facts struct {
	Facts []fact `xml:"fact"`
}

type fact struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type rule struct {
	IDRef    string `xml:"idref,attr"`
	Severity string `xml:"severity,attr,omitempty"`
	Result   string `xml:"result"`
	Message  string `xml:"message,omitempty"`
}

// ResultsFileName is the oscap-style results name for one device and benchmark.
func ResultsFileName(host, benchmarkID string) string {
	return host + "." + benchmarkID + ".results.xml"
}

// ChecklistFileName is the review checklist named for the device it describes.
func ChecklistFileName(host string) string {
	return host + ".cklb"
}

// RequireResultsPath accepts only a results file named for its device, inside a directory named for that device.
func RequireResultsPath(path, host, benchmarkID string) error {
	if filepath.Base(path) != ResultsFileName(host, benchmarkID) || filepath.Base(filepath.Dir(path)) != host {
		return fmt.Errorf("results file must be %s/%s", host, ResultsFileName(host, benchmarkID))
	}
	return nil
}

// RequireChecklistPath accepts only a checklist named for its device, inside a directory named for that device.
func RequireChecklistPath(path, host string) error {
	if filepath.Base(path) != ChecklistFileName(host) || filepath.Base(filepath.Dir(path)) != host {
		return fmt.Errorf("checklist file must be %s/%s", host, ChecklistFileName(host))
	}
	return nil
}

// FromChecklist renders oscap-like results from a review checklist.
// Rule ids are the official SV identifiers so a later conversion can join them.
func FromChecklist(id Identity, benchmarkID string, meta ResultMeta, doc map[string]any, when time.Time) ([]byte, error) {
	if err := id.Normalize(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(benchmarkID) == "" {
		return nil, fmt.Errorf("network XCCDF host and benchmark are required")
	}
	if !sha256Pattern.MatchString(meta.ConfigSHA256) || (meta.TailoringSHA256 != "" && !sha256Pattern.MatchString(meta.TailoringSHA256)) {
		return nil, fmt.Errorf("network XCCDF config and tailoring hashes must be lowercase SHA-256")
	}
	stigs, _ := doc["stigs"].([]any)
	if len(stigs) != 1 {
		return nil, fmt.Errorf("network XCCDF requires one STIG")
	}
	rows, _ := stigs[0].(map[string]any)["rules"].([]any)
	if len(rows) == 0 {
		return nil, fmt.Errorf("network XCCDF has no rules")
	}
	ipFact := "urn:xccdf:fact:asset:identifier:ipv4"
	if strings.Contains(id.IPAddress, ":") {
		ipFact = "urn:xccdf:fact:asset:identifier:ipv6"
	}
	complete := "false"
	if meta.ConfigComplete {
		complete = "true"
	}
	bound := []fact{
		{Name: "urn:xccdf:fact:asset:identifier:host_name", Type: "string", Value: id.HostName},
		{Name: "urn:xccdf:fact:asset:identifier:fqdn", Type: "string", Value: id.FQDN},
		{Name: ipFact, Type: "string", Value: id.IPAddress},
		{Name: "urn:xccdf:fact:asset:identifier:mac", Type: "string", Value: id.MACAddress},
		{Name: "urn:burden:network:role", Type: "string", Value: id.Role},
		{Name: "urn:burden:network:target-type", Type: "string", Value: id.TargetType},
		{Name: "urn:burden:network:technology-area", Type: "string", Value: id.TechnologyArea},
		{Name: "urn:burden:network:benchmark-id", Type: "string", Value: benchmarkID},
		{Name: "urn:burden:network:running-config-sha256", Type: "string", Value: meta.ConfigSHA256},
		{Name: "urn:burden:network:config-complete", Type: "string", Value: complete},
	}
	if meta.TailoringSHA256 != "" {
		bound = append(bound, fact{Name: "urn:burden:network:tailoring-sha256", Type: "string", Value: meta.TailoringSHA256})
	}
	stamp := when.UTC().Format(time.RFC3339)
	out := document{
		XMLNS: xmlns, ID: "xccdf_burden.network_benchmark_" + benchmarkID,
		Title: "Network STIG scan results - " + id.HostName + " - " + benchmarkID, Version: "1",
		Test: result{
			ID: "xccdf_burden.network_testresult_" + id.HostName, Start: stamp, End: stamp,
			Target: id.HostName, Address: id.IPAddress,
			Facts:   facts{Facts: bound},
			Profile: profile{IDRef: "xccdf_burden.network_profile_stig"},
		},
	}
	for _, item := range rows {
		row := item.(map[string]any)
		out.Test.Rules = append(out.Test.Rules, rule{
			IDRef: row["rule_id"].(string), Severity: row["severity"].(string),
			Result: xccdfResult(row["status"].(string)), Message: row["comments"].(string),
		})
	}
	body, err := xml.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

// Parse reads a network scan result. It does not accept an official benchmark
// that has no TestResult.
func Parse(data []byte) (Scan, error) {
	var doc document
	if err := xml.Unmarshal(data, &doc); err != nil {
		return Scan{}, fmt.Errorf("network XCCDF: %w", err)
	}
	if doc.XMLNS != xmlns || !strings.HasPrefix(doc.ID, "xccdf_burden.network_benchmark_") || doc.Test.Target == "" || len(doc.Test.Rules) == 0 {
		return Scan{}, fmt.Errorf("network XCCDF: expected a burden network TestResult")
	}
	scan := Scan{Host: strings.TrimSpace(doc.Test.Target), Identity: Identity{IPAddress: strings.TrimSpace(doc.Test.Address)}, Rules: map[string]Item{}}
	seenFacts := map[string]bool{}
	for _, item := range doc.Test.Facts.Facts {
		name := strings.TrimSpace(item.Name)
		if seenFacts[name] {
			return Scan{}, fmt.Errorf("network XCCDF: duplicate fact %s", name)
		}
		seenFacts[name] = true
		value := strings.TrimSpace(item.Value)
		switch name {
		case "urn:xccdf:fact:asset:identifier:host_name":
			scan.Identity.HostName = value
		case "urn:xccdf:fact:asset:identifier:fqdn":
			scan.Identity.FQDN = value
		case "urn:xccdf:fact:asset:identifier:ipv4", "urn:xccdf:fact:asset:identifier:ipv6":
			if scan.Identity.IPAddress != "" && scan.Identity.IPAddress != value {
				return Scan{}, fmt.Errorf("network XCCDF: target address and IP fact disagree")
			}
			scan.Identity.IPAddress = value
		case "urn:xccdf:fact:asset:identifier:mac":
			scan.Identity.MACAddress = value
		case "urn:burden:network:role":
			scan.Identity.Role = value
		case "urn:burden:network:target-type":
			scan.Identity.TargetType = value
		case "urn:burden:network:technology-area":
			scan.Identity.TechnologyArea = value
		case "urn:burden:network:benchmark-id":
			scan.BenchmarkID = value
		case "urn:burden:network:running-config-sha256":
			scan.ConfigSHA256 = value
		case "urn:burden:network:config-complete":
			switch value {
			case "true":
				scan.ConfigComplete = true
			case "false":
				scan.ConfigComplete = false
			default:
				return Scan{}, fmt.Errorf("network XCCDF: config-complete must be true or false")
			}
		case "urn:burden:network:tailoring-sha256":
			scan.TailoringSHA256 = value
		}
	}
	if doc.Test.Address == "" || !seenFacts["urn:xccdf:fact:asset:identifier:host_name"] || (!seenFacts["urn:xccdf:fact:asset:identifier:ipv4"] && !seenFacts["urn:xccdf:fact:asset:identifier:ipv6"]) || !seenFacts["urn:xccdf:fact:asset:identifier:fqdn"] || !seenFacts["urn:xccdf:fact:asset:identifier:mac"] || !seenFacts["urn:burden:network:running-config-sha256"] || !seenFacts["urn:burden:network:config-complete"] {
		return Scan{}, fmt.Errorf("network XCCDF: target address, hostname, FQDN, IP, MAC, config hash, and completeness are required")
	}
	if !sha256Pattern.MatchString(scan.ConfigSHA256) || (scan.TailoringSHA256 != "" && !sha256Pattern.MatchString(scan.TailoringSHA256)) {
		return Scan{}, fmt.Errorf("network XCCDF: config and tailoring hashes must be lowercase SHA-256")
	}
	if err := scan.Identity.Normalize(); err != nil {
		return Scan{}, err
	}
	if scan.Identity.HostName != scan.Host {
		return Scan{}, fmt.Errorf("network XCCDF: host name fact must match the target")
	}
	if scan.BenchmarkID == "" {
		return Scan{}, fmt.Errorf("network XCCDF: benchmark id fact missing")
	}
	for _, rule := range doc.Test.Rules {
		if rule.IDRef == "" || rule.Result == "" {
			return Scan{}, fmt.Errorf("network XCCDF: rule-result missing idref or result")
		}
		if _, exists := scan.Rules[rule.IDRef]; exists {
			return Scan{}, fmt.Errorf("network XCCDF: duplicate rule-result %s", rule.IDRef)
		}
		scan.Rules[rule.IDRef] = Item{RuleID: rule.IDRef, Severity: rule.Severity, Result: rule.Result, Message: rule.Message}
	}
	return scan, nil
}

var (
	hostNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	fqdnPattern     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	labelPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Normalize canonicalizes a device identity and rejects a checklist that would ship with a blank target page.
func (id *Identity) Normalize() error {
	id.HostName = strings.TrimSpace(id.HostName)
	id.FQDN = strings.TrimSpace(id.FQDN)
	id.Role = strings.TrimSpace(id.Role)
	id.TargetType = strings.TrimSpace(id.TargetType)
	id.TechnologyArea = strings.TrimSpace(id.TechnologyArea)
	if id.TechnologyArea == "" {
		id.TechnologyArea = "Network"
	}
	if !hostNamePattern.MatchString(id.HostName) || strings.Contains(id.HostName, "..") {
		return fmt.Errorf("network XCCDF: device hostname is required")
	}
	if len(id.FQDN) > 253 || !fqdnPattern.MatchString(id.FQDN) || !strings.HasPrefix(id.FQDN, id.HostName+".") {
		return fmt.Errorf("network XCCDF: FQDN must be %s.<domain>", id.HostName)
	}
	ip := net.ParseIP(strings.TrimSpace(id.IPAddress))
	if ip == nil {
		return fmt.Errorf("network XCCDF: management IP is required")
	}
	if v4 := ip.To4(); v4 != nil {
		id.IPAddress = v4.String()
	} else {
		id.IPAddress = ip.String()
	}
	mac, err := canonicalMAC(id.MACAddress)
	if err != nil {
		return err
	}
	id.MACAddress = mac
	if !labelPattern.MatchString(id.Role) || !labelPattern.MatchString(id.TargetType) || !labelPattern.MatchString(id.TechnologyArea) {
		return fmt.Errorf("network XCCDF: role, target type, and technology area are required")
	}
	return nil
}

func canonicalMAC(value string) (string, error) {
	raw := strings.ToLower(strings.TrimSpace(value))
	if dotted := regexp.MustCompile(`^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$`); dotted.MatchString(raw) {
		raw = strings.ReplaceAll(raw, ".", "")
		var parts []string
		for i := 0; i < len(raw); i += 2 {
			parts = append(parts, raw[i:i+2])
		}
		raw = strings.Join(parts, ":")
	}
	raw = strings.ReplaceAll(raw, "-", ":")
	hw, err := net.ParseMAC(raw)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("network XCCDF: management MAC is required")
	}
	return hw.String(), nil
}

func xccdfResult(status string) string {
	switch status {
	case "not_a_finding":
		return "pass"
	case "open":
		return "fail"
	case "not_applicable":
		return "notapplicable"
	default:
		return "notchecked"
	}
}

// ChecklistStatus maps an oscap result token onto a CKLB status.
func ChecklistStatus(result string) (string, bool) {
	switch strings.TrimSpace(result) {
	case "pass":
		return "not_a_finding", true
	case "fail":
		return "open", true
	case "notapplicable":
		return "not_applicable", true
	case "notchecked", "notselected", "informational":
		return "not_reviewed", true
	default:
		return "", false
	}
}
