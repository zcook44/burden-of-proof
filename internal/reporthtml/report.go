// Package reporthtml reads OpenSCAP's HTML report as supplemental OVAL evidence.
// The XCCDF XML remains the authority for rule statuses and mappings.
package reporthtml

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

type Item struct {
	Comparison  string
	Description string
}
type Check struct {
	Name   string
	ID     string
	Result string
	Items  []Item
}
type Rule struct {
	Result string
	Checks []Check
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
func hasClass(n *html.Node, wanted string) bool {
	if n.Type != html.ElementNode {
		return false
	}
	for _, c := range strings.Fields(attr(n, "class")) {
		if c == wanted {
			return true
		}
	}
	return false
}
func visit(n *html.Node, f func(*html.Node)) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		f(c)
		visit(c, f)
	}
}
func first(n *html.Node, f func(*html.Node) bool) *html.Node {
	var hit *html.Node
	visit(n, func(c *html.Node) {
		if hit == nil && f(c) {
			hit = c
		}
	})
	return hit
}
func byClass(n *html.Node, c string) *html.Node {
	return first(n, func(x *html.Node) bool { return hasClass(x, c) })
}
func byTag(n *html.Node, tag string) *html.Node {
	return first(n, func(x *html.Node) bool { return x.Type == html.ElementNode && x.Data == tag })
}
func text(n *html.Node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	visit(n, func(c *html.Node) {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
			b.WriteByte(' ')
		}
	})
	return strings.Join(strings.Fields(b.String()), " ")
}
func directChildren(n *html.Node, tag string) []*html.Node {
	out := []*html.Node{}
	if n != nil {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == tag {
				out = append(out, c)
			}
		}
	}
	return out
}
func parseCheck(h4 *html.Node) Check {
	c := Check{Items: []Item{}}
	c.Name = text(byClass(h4, "label-primary"))
	c.ID = text(byClass(h4, "label-default"))
	for _, kind := range []string{"label-success", "label-danger", "label-warning", "label-info"} {
		if s := byClass(h4, kind); s != nil {
			c.Result = text(s)
			break
		}
	}
	// OpenSCAP renders one test h4 and its item table within the same panel-body.
	var panel *html.Node
	for p := h4.Parent; p != nil; p = p.Parent {
		if hasClass(p, "panel-body") {
			panel = p
			break
		}
	}
	if panel == nil {
		return c
	}
	table := byTag(panel, "table")
	if table == nil {
		return c
	}
	headers := []string{}
	if thead := byTag(table, "thead"); thead != nil {
		for _, th := range directChildren(byTag(thead, "tr"), "th") {
			headers = append(headers, text(th))
		}
	}
	tbody := byTag(table, "tbody")
	if tbody == nil {
		return c
	}
	for _, row := range directChildren(tbody, "tr") {
		cells := directChildren(row, "td")
		if len(cells) == 0 || len(cells) != len(headers) {
			continue
		}
		item := Item{}
		values := []string{}
		for i, cell := range cells {
			v := text(cell)
			if headers[i] == "Result of item-state comparison" {
				item.Comparison = v
			} else {
				values = append(values, headers[i]+": "+v)
			}
		}
		if item.Comparison != "" {
			item.Description = strings.Join(values, "; ")
			c.Items = append(c.Items, item)
		}
	}
	return c
}

// Extract associates report evidence with exact SSG rule IDs; duplicates fail closed.
func Extract(data []byte) (map[string]Rule, error) {
	root, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out := map[string]Rule{}
	var problem error
	visit(root, func(n *html.Node) {
		if !hasClass(n, "rule-detail") {
			return
		}
		id := text(byClass(n, "rule-id"))
		result := text(byClass(n, "rule-result"))
		if id == "" || result == "" {
			problem = fmt.Errorf("report rule ID/result missing")
			return
		}
		if _, ok := out[id]; ok {
			problem = fmt.Errorf("duplicate report rule: %s", id)
			return
		}
		rule := Rule{Result: result, Checks: []Check{}}
		if section := byClass(n, "check-system-details"); section != nil {
			visit(section, func(h *html.Node) {
				if h.Type == html.ElementNode && h.Data == "h4" {
					c := parseCheck(h)
					if c.Name != "" || c.ID != "" {
						rule.Checks = append(rule.Checks, c)
					}
				}
			})
		}
		out[id] = rule
	})
	if problem != nil {
		return nil, problem
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("report contains no rule details")
	}
	return out, nil
}
