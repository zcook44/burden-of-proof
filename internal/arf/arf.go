// Package arf extracts joined OVAL test and collected-item observations from
// an OpenSCAP ARF. It never infers a host value from a pass/fail alone.
package arf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	xccdfNS  = "http://checklists.nist.gov/xccdf/1.2"
	resultNS = "http://oval.mitre.org/XMLSchema/oval-results-5"
	defNS    = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
	charNS   = "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
	arfNS    = "http://scap.nist.gov/schema/asset-reporting-format/1.1"
)

type Item struct {
	Result string
	Fields string
}
type Test struct {
	ID             string
	Result         string
	CheckExistence string
	ObjectID       string
	ObjectFlag     string
	Items          []Item
}
type Rule struct {
	Result     string
	Definition string
	Tests      []Test
}
type Report struct {
	Target string
	Rules  map[string]Rule
}
type xref struct {
	Href string `xml:"href,attr"`
	Name string `xml:"name,attr"`
}
type xcheck struct {
	Refs []xref `xml:"check-content-ref"`
}
type xrule struct {
	ID     string   `xml:"idref,attr"`
	Result string   `xml:"result"`
	Checks []xcheck `xml:"check"`
}
type criterion struct {
	Ref string `xml:"test_ref,attr"`
}
type extend struct {
	Ref string `xml:"definition_ref,attr"`
}
type criteria struct {
	Criteria []criteria  `xml:"criteria"`
	Tests    []criterion `xml:"criterion"`
	Extends  []extend    `xml:"extend_definition"`
}
type definition struct {
	ID       string   `xml:"definition_id,attr"`
	Result   string   `xml:"result,attr"`
	Criteria criteria `xml:"criteria"`
}
type testedItem struct {
	ID     string `xml:"item_id,attr"`
	Result string `xml:"result,attr"`
}
type ovalTest struct {
	ID             string       `xml:"test_id,attr"`
	Result         string       `xml:"result,attr"`
	CheckExistence string       `xml:"check_existence,attr"`
	Items          []testedItem `xml:"tested_item"`
}
type objRef struct {
	ID string `xml:"object_ref,attr"`
}
type sourceTest struct {
	ID     string `xml:"id,attr"`
	Object objRef `xml:"object"`
}
type itemRef struct {
	ID string `xml:"item_ref,attr"`
}
type collectedObject struct {
	ID   string    `xml:"id,attr"`
	Flag string    `xml:"flag,attr"`
	Refs []itemRef `xml:"reference"`
}
type field struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}
type collectedItem struct {
	ID     string  `xml:"id,attr"`
	Status string  `xml:"status,attr"`
	Fields []field `xml:",any"`
}

func attribute(attrs []xml.Attr, key string) string {
	for _, a := range attrs {
		if a.Name.Local == key {
			return a.Value
		}
	}
	return ""
}
func contains(refs []itemRef, id string) bool {
	for _, r := range refs {
		if r.ID == id {
			return true
		}
	}
	return false
}
func gather(c criteria, tests, exts map[string]bool) {
	for _, t := range c.Tests {
		tests[t.Ref] = true
	}
	for _, e := range c.Extends {
		exts[e.Ref] = true
	}
	for _, child := range c.Criteria {
		gather(child, tests, exts)
	}
}

// Extract reads a single OpenSCAP ARF, joining XCCDF -> OVAL definition ->
// tests -> tested item -> the object's collected system-characteristics item.
func Extract(data []byte) (Report, error) {
	out := Report{Rules: map[string]Rule{}}
	if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return out, fmt.Errorf("DTD/entity forbidden")
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	var stack []xml.Name
	reportID := ""
	defs := map[string]definition{}
	tests := map[string]ovalTest{}
	source := map[string]sourceTest{}
	objects := map[string]collectedObject{}
	items := map[string]collectedItem{}
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			parent := xml.Name{}
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			if t.Name.Space == arfNS && t.Name.Local == "report" {
				reportID = attribute(t.Attr, "id")
			}
			if reportID == "xccdf1" && t.Name.Space == xccdfNS && t.Name.Local == "target" {
				var target string
				if err := dec.DecodeElement(&target, &t); err != nil {
					return out, err
				}
				if out.Target != "" && out.Target != target {
					return out, fmt.Errorf("multiple ARF targets")
				}
				out.Target = target
				continue
			}
			if reportID == "xccdf1" && t.Name.Space == xccdfNS && t.Name.Local == "rule-result" {
				var rr xrule
				if err := dec.DecodeElement(&rr, &t); err != nil {
					return out, err
				}
				if rr.ID == "" || rr.Result == "" {
					return out, fmt.Errorf("invalid ARF rule result")
				}
				if _, exists := out.Rules[rr.ID]; exists {
					return out, fmt.Errorf("duplicate ARF rule ID %s", rr.ID)
				}
				r := Rule{Result: rr.Result}
				for _, c := range rr.Checks {
					for _, ref := range c.Refs {
						if ref.Href == "#oval0" {
							if r.Definition != "" && r.Definition != ref.Name {
								return out, fmt.Errorf("ambiguous ARF check for %s", rr.ID)
							}
							r.Definition = ref.Name
						}
					}
				}
				out.Rules[rr.ID] = r
				continue
			}
			if reportID == "oval0" {
				switch {
				case t.Name.Space == resultNS && t.Name.Local == "definition" && parent.Space == resultNS && parent.Local == "definitions":
					var d definition
					if err := dec.DecodeElement(&d, &t); err != nil {
						return out, err
					}
					if d.ID == "" || defs[d.ID].ID != "" {
						return out, fmt.Errorf("duplicate/empty OVAL definition")
					}
					defs[d.ID] = d
					continue
				case t.Name.Space == resultNS && t.Name.Local == "test" && parent.Space == resultNS && parent.Local == "tests":
					var v ovalTest
					if err := dec.DecodeElement(&v, &t); err != nil {
						return out, err
					}
					if v.ID == "" || tests[v.ID].ID != "" {
						return out, fmt.Errorf("duplicate/empty OVAL test")
					}
					tests[v.ID] = v
					continue
				case strings.HasPrefix(t.Name.Space, defNS+"#") && strings.HasSuffix(t.Name.Local, "_test") && parent.Space == defNS && parent.Local == "tests":
					var v sourceTest
					if err := dec.DecodeElement(&v, &t); err != nil {
						return out, err
					}
					if v.ID == "" || source[v.ID].ID != "" {
						return out, fmt.Errorf("duplicate/empty source test")
					}
					source[v.ID] = v
					continue
				case t.Name.Space == charNS && t.Name.Local == "object" && parent.Space == charNS && parent.Local == "collected_objects":
					var v collectedObject
					if err := dec.DecodeElement(&v, &t); err != nil {
						return out, err
					}
					if v.ID == "" || objects[v.ID].ID != "" {
						return out, fmt.Errorf("duplicate/empty collected object")
					}
					objects[v.ID] = v
					continue
				case strings.HasPrefix(t.Name.Space, charNS+"#") && strings.HasSuffix(t.Name.Local, "_item") && parent.Space == charNS && parent.Local == "system_data":
					var v collectedItem
					if err := dec.DecodeElement(&v, &t); err != nil {
						return out, err
					}
					if v.ID == "" || items[v.ID].ID != "" {
						return out, fmt.Errorf("duplicate/empty collected item")
					}
					items[v.ID] = v
					continue
				}
			}
			stack = append(stack, t.Name)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != t.Name {
				return out, fmt.Errorf("unbalanced ARF element")
			}
			stack = stack[:len(stack)-1]
			if t.Name.Space == arfNS && t.Name.Local == "report" {
				reportID = ""
			}
		}
	}
	if out.Target == "" || len(out.Rules) == 0 || len(defs) == 0 {
		return out, fmt.Errorf("ARF lacks XCCDF/OVAL results")
	}
	var resolve func(string, map[string]bool, map[string]bool) error
	resolve = func(id string, seen, needed map[string]bool) error {
		if seen[id] {
			return fmt.Errorf("cyclic OVAL definition %s", id)
		}
		d, ok := defs[id]
		if !ok {
			return fmt.Errorf("OVAL definition missing: %s", id)
		}
		seen[id] = true
		refs := map[string]bool{}
		exts := map[string]bool{}
		gather(d.Criteria, refs, exts)
		for ref := range refs {
			if ref == "" {
				return fmt.Errorf("empty test reference")
			}
			needed[ref] = true
		}
		for ref := range exts {
			if err := resolve(ref, seen, needed); err != nil {
				return err
			}
		}
		delete(seen, id)
		return nil
	}
	for id, r := range out.Rules {
		if r.Definition == "" {
			continue
		}
		needed := map[string]bool{}
		if err := resolve(r.Definition, map[string]bool{}, needed); err != nil {
			return out, fmt.Errorf("%s: %w", id, err)
		}
		ids := make([]string, 0, len(needed))
		for testID := range needed {
			ids = append(ids, testID)
		}
		sort.Strings(ids)
		for _, testID := range ids {
			v, ok := tests[testID]
			if !ok {
				return out, fmt.Errorf("%s: missing OVAL test %s", id, testID)
			}
			st, sourceExists := source[testID]
			entry := Test{ID: testID, Result: v.Result, CheckExistence: v.CheckExistence, Items: []Item{}}
			if sourceExists {
				entry.ObjectID = st.Object.ID
				entry.ObjectFlag = objects[st.Object.ID].Flag
			}
			for _, tested := range v.Items {
				collected, ok := items[tested.ID]
				if !ok {
					return out, fmt.Errorf("%s: missing collected item %s", id, tested.ID)
				}
				if !sourceExists || st.Object.ID == "" || !contains(objects[st.Object.ID].Refs, tested.ID) {
					return out, fmt.Errorf("%s: collected item %s not bound to test object", id, tested.ID)
				}
				fields := []string{}
				for _, f := range collected.Fields {
					if f.Value != "" {
						fields = append(fields, f.XMLName.Local+": "+fmt.Sprintf("%q", f.Value))
					}
				}
				entry.Items = append(entry.Items, Item{Result: tested.Result, Fields: strings.Join(fields, "; ")})
			}
			r.Tests = append(r.Tests, entry)
		}
		out.Rules[id] = r
	}
	return out, nil
}
