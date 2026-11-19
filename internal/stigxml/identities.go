// Package stigxml reads benchmark identity and control IDs from a DISA manual XCCDF.
// It does not score results and it does not resolve external entities.
package stigxml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Identities returns the Benchmark id and a map of group id (V-…) to rule id (SV-…).
// Nested groups are visited. DTD and entity declarations are rejected.
func Identities(data []byte) (string, map[string]string, error) {
	if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return "", nil, fmt.Errorf("DTD/entity forbidden")
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("unsupported charset %q", charset)
	}
	var benchmarkID string
	controls := map[string]string{}
	groupStack := []string{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Benchmark":
				if benchmarkID == "" {
					benchmarkID = attr(t, "id")
				}
			case "Group":
				groupStack = append(groupStack, attr(t, "id"))
			case "Rule":
				if len(groupStack) == 0 {
					return "", nil, fmt.Errorf("rule outside a group")
				}
				groupID := groupStack[len(groupStack)-1]
				ruleID := attr(t, "id")
				if groupID == "" || ruleID == "" {
					return "", nil, fmt.Errorf("group or rule id missing")
				}
				if prev, ok := controls[groupID]; ok && prev != ruleID {
					return "", nil, fmt.Errorf("duplicate group %s", groupID)
				}
				controls[groupID] = ruleID
			}
		case xml.EndElement:
			if t.Name.Local == "Group" && len(groupStack) > 0 {
				groupStack = groupStack[:len(groupStack)-1]
			}
		}
	}
	if benchmarkID == "" {
		return "", nil, fmt.Errorf("benchmark id missing")
	}
	if len(controls) == 0 {
		return "", nil, fmt.Errorf("benchmark %s has no controls", benchmarkID)
	}
	return benchmarkID, controls, nil
}

func attr(el xml.StartElement, name string) string {
	for _, a := range el.Attr {
		if a.Name.Local == name {
			return strings.TrimSpace(a.Value)
		}
	}
	return ""
}
