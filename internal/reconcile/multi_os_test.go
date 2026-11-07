package reconcile

import (
	"fmt"
	"strings"
	"testing"
)

func TestConvertMatchesSupportedRHELFamiliesAndRejectsCrossOS(t *testing.T) {
	for _, major := range []int{7, 8, 9, 10} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			source := strings.ReplaceAll(scan, "RHEL-9", fmt.Sprintf("RHEL-%d", major))
			benchmark := strings.ReplaceAll(official, "RHEL_9_STIG", fmt.Sprintf("RHEL_%d_STIG", major))
			report, err := Convert([]byte(source), []byte(benchmark))
			if err != nil {
				t.Fatalf("matching RHEL %d: %v", major, err)
			}
			if report.DISABenchmark != fmt.Sprintf("RHEL_%d_STIG", major) || len(report.Controls) != 3 || report.Controls[0].Status != "not_a_finding" {
				t.Fatalf("bad mapping: %+v", report)
			}
			if _, err := Convert([]byte(source), []byte(official)); major != 9 && err == nil {
				t.Fatal("cross-OS benchmark accepted")
			}
		})
	}
	legacy := strings.ReplaceAll(scan, "RHEL-9", "RHEL-7")
	legacy = strings.ReplaceAll(legacy, "content_profile_stig", "content_profile_stig-rhel7-disa")
	if _, err := Convert([]byte(legacy), []byte(strings.ReplaceAll(official, "RHEL_9_STIG", "RHEL_7_STIG"))); err != nil {
		t.Fatalf("older RHEL 7 SSG STIG profile rejected: %v", err)
	}
	for _, invalid := range []string{"RHEL-6", "RHEL-11", "RHEL-9-extra"} {
		if _, err := Convert([]byte(strings.ReplaceAll(scan, "RHEL-9", invalid)), []byte(official)); err == nil {
			t.Fatalf("unsupported %s accepted", invalid)
		}
	}
}
