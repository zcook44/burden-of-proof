package arf

import (
	"os"
	"strings"
	"testing"
)

const fixture = `<asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"><reports><report id="xccdf1"><content><TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"><target>node.test</target><rule-result idref="ssg_a"><result>fail</result><check><check-content-ref href="#oval0" name="oval:def:1"/></check></rule-result></TestResult></content></report><report id="oval0"><content><oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5"><oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><tests><textfilecontent54_test xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" id="oval:test:tst:1"><object object_ref="oval:obj:1"/></textfilecontent54_test></tests></oval_definitions><results><system><definitions><definition definition_id="oval:def:1" result="false"><criteria><criterion test_ref="oval:test:tst:1"/></criteria></definition></definitions><tests><test test_id="oval:test:tst:1" result="false"><tested_item item_id="101" result="false"/></test></tests><oval_system_characteristics xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"><collected_objects><object id="oval:obj:1"><reference item_ref="101"/></object></collected_objects><system_data><textfilecontent_item xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#independent" id="101" status="exists"><filepath>/etc/audit.conf</filepath><text>disabled</text></textfilecontent_item></system_data></oval_system_characteristics></system></results></oval_results></content></report></reports></asset-report-collection>`

func TestExtractJoinsDefinitionTestCollectedItem(t *testing.T) {
	got, err := Extract([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	r := got.Rules["ssg_a"]
	if r.Result != "fail" || r.Definition != "oval:def:1" || len(r.Tests) != 1 {
		t.Fatalf("rule: %+v", r)
	}
	test := r.Tests[0]
	if test.ID != "oval:test:tst:1" || test.Result != "false" || len(test.Items) != 1 || test.Items[0].Result != "false" || !strings.Contains(test.Items[0].Fields, `text: "disabled"`) {
		t.Fatalf("test: %+v", test)
	}
}
func TestRealARFOptIn(t *testing.T) {
	path := os.Getenv("SSG_REAL_ARF")
	if path == "" {
		t.Skip("no private ARF supplied")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Extract(data)
	if err != nil {
		t.Fatal(err)
	}
	joined, values := 0, 0
	for _, r := range report.Rules {
		if len(r.Tests) > 0 {
			joined++
		}
		for _, test := range r.Tests {
			values += len(test.Items)
		}
	}
	t.Logf("target %s, rules %d, joined %d, collected items %d", report.Target, len(report.Rules), joined, values)
	if joined < 300 || values == 0 {
		t.Fatal("ARF join incomplete")
	}
}

func TestExtractReportsAbsentObjectWhenNoItemExists(t *testing.T) {
	absent := strings.Replace(fixture, `<tested_item item_id="101" result="false"/>`, ``, 1)
	absent = strings.Replace(absent, `<reference item_ref="101"/>`, ``, 1)
	absent = strings.Replace(absent, `<object id="oval:obj:1">`, `<object id="oval:obj:1" flag="does not exist">`, 1)
	absent = strings.Replace(absent, `<test test_id="oval:test:tst:1" result="false">`, `<test test_id="oval:test:tst:1" result="false" check_existence="all_exist">`, 1)
	got, err := Extract([]byte(absent))
	if err != nil {
		t.Fatal(err)
	}
	test := got.Rules["ssg_a"].Tests[0]
	if test.ObjectFlag != "does not exist" || test.CheckExistence != "all_exist" || len(test.Items) != 0 {
		t.Fatalf("absence lost: %+v", test)
	}
}

func TestExtractPreservesWhitespaceInReturnedHostValue(t *testing.T) {
	raw := strings.Replace(fixture, `<text>disabled</text>`, `<text>  disabled  </text>`, 1)
	got, err := Extract([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	fields := got.Rules["ssg_a"].Tests[0].Items[0].Fields
	if !strings.Contains(fields, `text: "  disabled  "`) {
		t.Fatalf("host output altered: %q", fields)
	}
}

func TestExtractRejectsUnboundItem(t *testing.T) {
	broken := strings.Replace(fixture, `item_ref="101"`, `item_ref="999"`, 1)
	if _, err := Extract([]byte(broken)); err == nil {
		t.Fatal("unbound item accepted")
	}
}
