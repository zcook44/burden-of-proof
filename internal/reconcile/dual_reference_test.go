package reconcile

import (
    "strings"
    "testing"
)

func TestDualVAndLegacySVReferencesSameNumberRemainAmbiguous(t *testing.T) {
    mixed := strings.Replace(scan, `>V-100</reference>`, `>V-100</reference><reference href="https://public.cyber.mil/stigs/srg-stig-tools/">SV-100r1_rule</reference>`, 1)
    report, err := Convert([]byte(mixed), []byte(official))
    if err != nil { t.Fatal(err) }
    if report.Controls[0].Status != "not_reviewed" {
        t.Fatalf("two explicit references promoted to %s", report.Controls[0].Status)
    }
    if len(report.Controls[0].Sources) != 1 || len(report.Controls[0].Sources[0].OriginalReferences) != 2 {
        t.Fatalf("reference audit trail lost: %+v", report.Controls[0].Sources)
    }
}
