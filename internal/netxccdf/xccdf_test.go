package netxccdf

import "testing"

func TestDeviceFileNames(t *testing.T) {
	host, bench := "sw1", "Cisco_IOS_XE_Switch_L2S_STIG"
	if err := RequireResultsPath("/var/scans/sw1/sw1."+bench+".results.xml", host, bench); err != nil {
		t.Fatal(err)
	}
	if err := RequireResultsPath("/var/scans/sw1/"+bench+".results.xml", host, bench); err == nil {
		t.Fatal("accepted a results file that omits the device name")
	}
	if err := RequireResultsPath("/var/scans/other/sw1."+bench+".results.xml", host, bench); err == nil {
		t.Fatal("accepted a results file outside the device directory")
	}
	if err := RequireChecklistPath("/var/checklists/"+bench+"/sw1/sw1.cklb", host); err != nil {
		t.Fatal(err)
	}
	if err := RequireChecklistPath("/var/checklists/"+bench+"/sw1/scan.cklb", host); err == nil {
		t.Fatal("accepted a generic checklist name")
	}
}

func TestIdentityNormalizesCiscoMAC(t *testing.T) {
	id := Identity{HostName: "sw1", FQDN: "sw1.example.test", IPAddress: "192.0.2.10", MACAddress: "0200.0000.0010", Role: "Access switch", TargetType: "Cisco IOS-XE switch"}
	if err := id.Normalize(); err != nil {
		t.Fatal(err)
	}
	if id.MACAddress != "02:00:00:00:00:10" || id.TechnologyArea != "Network" {
		t.Fatalf("identity: %#v", id)
	}
	id.FQDN = "other.example.test"
	if err := id.Normalize(); err == nil {
		t.Fatal("accepted an FQDN for a different device")
	}
}
