package reporthtml

import (
	"os"
	"strings"
	"testing"
)

const sample = `<html><body><div class="panel rule-detail rule-detail-fail rule-detail-id-ssg_a"><table><tr><td>Rule ID</td><td class="rule-id">ssg_a</td></tr><tr><td>Result</td><td class="rule-result rule-result-fail">fail</td></tr></table><div class="check-system-details"><div class="panel"><div class="panel-body"><h4><span class="label label-primary">verify audit setting</span><span class="label label-default">oval:test:tst:1</span><span class="label label-danger">false</span></h4><h5>Following items have been found on the system:</h5><table><thead><tr><th>Result of item-state comparison</th><th>Path</th><th>Content</th></tr></thead><tbody><tr><td><span>false</span></td><td>/etc/audit.conf</td><td>disabled</td></tr><tr><td><span>not evaluated</span></td><td>/etc/other</td><td>unknown</td></tr></tbody></table></div></div></div></div></body></html>`

func TestExtractKeepsCheckAndEachItemComparison(t *testing.T) {
	got, err := Extract([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	r := got["ssg_a"]
	if r.Result != "fail" || len(r.Checks) != 1 {
		t.Fatalf("rule: %+v", r)
	}
	c := r.Checks[0]
	if c.Name != "verify audit setting" || c.ID != "oval:test:tst:1" || c.Result != "false" || len(c.Items) != 2 {
		t.Fatalf("check: %+v", c)
	}
	if c.Items[0].Comparison != "false" || !strings.Contains(c.Items[0].Description, "Path: /etc/audit.conf") || c.Items[1].Comparison != "not evaluated" {
		t.Fatalf("items: %+v", c.Items)
	}
}

func TestRealReportOptIn(t *testing.T) {
	path := os.Getenv("SSG_HTML_REPORT")
	if path == "" {
		t.Skip("no private report supplied")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Extract(data)
	if err != nil {
		t.Fatal(err)
	}
	nchecks, nitems := 0, 0
	for _, r := range rules {
		nchecks += len(r.Checks)
		for _, c := range r.Checks {
			nitems += len(c.Items)
		}
	}
	t.Logf("report: %d rules, %d checks, %d compared items", len(rules), nchecks, nitems)
	if len(rules) < 400 || nchecks == 0 || nitems == 0 {
		t.Fatal("real report parsing incomplete")
	}
}

func TestExtractRejectsDuplicateRuleIDs(t *testing.T) {
	duplicated := strings.Replace(sample, "</body>", strings.TrimPrefix(strings.TrimSuffix(sample, "</body></html>"), "<html><body>")+"</body>", 1)
	if _, err := Extract([]byte(duplicated)); err == nil {
		t.Fatal("duplicate accepted")
	}
}
