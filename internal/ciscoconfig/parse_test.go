package ciscoconfig

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseSkipsBannerBodyWhenDelimiterAppearsInBannerType(t *testing.T) {
	cfg, err := Parse([]byte("hostname sw\nbanner motd d\nspanning-tree loopguard default\nd\nversion 17.9\nend\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Uncertain || cfg.Has("spanning-tree loopguard default") || !cfg.Complete("ios") {
		t.Fatalf("banner body leaked into commands: %+v globals=%v", cfg, cfg.Globals)
	}
}

func TestParseSkipsMacroBody(t *testing.T) {
	cfg, err := Parse([]byte("hostname sw\nmacro name sample\nspanning-tree loopguard default\n@\nversion 17.9\nend\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Has("spanning-tree loopguard default") || cfg.Uncertain {
		t.Fatalf("macro body became configuration: %+v", cfg.Globals)
	}
}

func TestSyntheticSwitchSnapshotsParse(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "examples", "cisco-synthetic", "targets")
	for _, host := range []string{"ios-switch-01", "ios-xe-switch-01", "nx-access-01"} {
		cfg, err := Parse(mustRead(t, filepath.Join(root, host, "scan.running-config")))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Uncertain || cfg.Hostname != host {
			t.Fatalf("%s uncertain=%v (%s) hostname=%q", host, cfg.Uncertain, cfg.Uncertainty, cfg.Hostname)
		}
	}
}
func TestParsePortRolesRejectsDisagreement(t *testing.T) {
	_, err := ParsePortRoles([]byte("interface,role,user_facing,fiber\nGi1,uplink,yes,no\n"))
	if err == nil {
		t.Fatal("accepted user_facing yes on an uplink")
	}
}
