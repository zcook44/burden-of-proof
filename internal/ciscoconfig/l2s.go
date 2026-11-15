package ciscoconfig

import "strings"

func init() {
	registerL2S()
	registerNDM()
	registerDefinitive()
}

func registerL2S() {
	l2s := []string{"Cisco_IOS_XE_Switch_L2S_STIG", "Cisco_IOS_Switch_L2S_STIG", "Cisco_NX-OS_Switch_L2S_STIG"}
	allThree := func(version, title string, phrases []string, xe, ios, nx idPair, eval func(checkContext) (string, string, string)) {
		register(checkSpec{
			Version: version, Title: title, Common: phrases, Eval: eval,
			IDs: map[string]idPair{
				l2s[0]: xe, l2s[1]: ios, l2s[2]: nx,
			},
		})
	}

	allThree("CISC-L2-000030", "VLAN Trunk Protocol", []string{"show vtp status", "If VTP is enabled"},
		idPair{"V-220650", "SV-220650r539671_rule"},
		idPair{"V-220624", "SV-220624r1188386_rule"},
		idPair{"V-220676", "SV-220676r1188386_rule"},
		evalVTP)
	allThree("CISC-L2-000090", "Root Guard", []string{"spanning-tree guard root", "access layer switches"},
		idPair{"V-220655", "SV-220655r917683_rule"},
		idPair{"V-220629", "SV-220629r856223_rule"},
		idPair{"V-220680", "SV-220680r940009_rule"},
		evalRootGuard)
	allThree("CISC-L2-000100", "user-facing or untrusted access switch ports", []string{"spanning-tree bpduguard enable", "If the switch has not enabled BPDU Guard"},
		idPair{"V-220656", "SV-220656r856278_rule"},
		idPair{"V-220630", "SV-220630r856224_rule"},
		idPair{"V-220681", "SV-220681r856490_rule"},
		evalBPDUGuard)
	allThree("CISC-L2-000110", "Loop Guard enabled", []string{"spanning-tree loopguard default", "If STP Loop Guard is not enabled, this is a finding."},
		idPair{"V-220657", "SV-220657r856279_rule"},
		idPair{"V-220631", "SV-220631r856225_rule"},
		idPair{"V-220682", "SV-220682r856491_rule"},
		evalLoopGuard)
	allThree("CISC-L2-000120", "Unknown Unicast Flood Blocking", []string{"switchport block unicast", "If any access switch ports do not have UUFB enabled"},
		idPair{"V-220658", "SV-220658r856280_rule"},
		idPair{"V-220632", "SV-220632r856226_rule"},
		idPair{"V-220683", "SV-220683r856492_rule"},
		evalUUFB)
	allThree("CISC-L2-000130", "DHCP snooping", []string{"ip dhcp snooping", "DHCP snooping"},
		idPair{"V-220659", "SV-220659r928999_rule"},
		idPair{"V-220633", "SV-220633r929007_rule"},
		idPair{"V-220684", "SV-220684r856493_rule"},
		evalDHCPSnooping)
	allThree("CISC-L2-000140", "IP Source Guard", []string{"ip verify source", "IP Source Guard"},
		idPair{"V-220660", "SV-220660r929001_rule"},
		idPair{"V-220634", "SV-220634r929009_rule"},
		idPair{"V-220685", "SV-220685r1156799_rule"},
		evalIPSourceGuard)
	allThree("CISC-L2-000150", "Dynamic Address Resolution Protocol", []string{"ip arp inspection vlan", "If DAI is not enabled"},
		idPair{"V-220661", "SV-220661r929003_rule"},
		idPair{"V-220635", "SV-220635r929011_rule"},
		idPair{"V-220686", "SV-220686r856495_rule"},
		evalDAI)
	allThree("CISC-L2-000160", "Storm Control", []string{"storm-control", "broadcast"},
		idPair{"V-220662", "SV-220662r648766_rule"},
		idPair{"V-220636", "SV-220636r1205856_rule"},
		idPair{"V-220687", "SV-220687r1205858_rule"},
		evalStormControl)
	allThree("CISC-L2-000170", "IGMP or MLD Snooping", []string{"no ip igmp snooping", "IGMP"},
		idPair{"V-220663", "SV-220663r929005_rule"},
		idPair{"V-220637", "SV-220637r539671_rule"},
		idPair{"V-220688", "SV-220688r539671_rule"},
		evalIGMP)
	register(checkSpec{
		Version: "CISC-L2-000180", Title: "where VLANs span multiple switches",
		Common: []string{"spanning-tree mode rapid-pvst", "If either RSTP or MSTP has not been implemented where STP is required, this is a finding."},
		Eval:   evalRapidSTP,
		IDs: map[string]idPair{
			"Cisco_IOS_XE_Switch_L2S_STIG": {"V-220664", "SV-220664r539671_rule"},
			"Cisco_IOS_Switch_L2S_STIG":    {"V-220638", "SV-220638r539671_rule"},
		},
	})
	allThree("CISC-L2-000190", "Unidirectional Link Detection", []string{"udld", "fiber"},
		idPair{"V-220665", "SV-220665r539671_rule"},
		idPair{"V-220639", "SV-220639r1188389_rule"},
		idPair{"V-220689", "SV-220689r1188389_rule"},
		evalUDLD)
	register(checkSpec{
		Version: "CISC-L2-000200", Title: "trunk links enabled statically",
		Common: []string{"Negotiation of Trunking", "If trunk negotiation is enabled"},
		Eval:   evalTrunkNegotiation,
		IDs: map[string]idPair{
			"Cisco_IOS_XE_Switch_L2S_STIG": {"V-220666", "SV-220666r539671_rule"},
			"Cisco_IOS_Switch_L2S_STIG":    {"V-220640", "SV-220640r1188390_rule"},
		},
	})
	allThree("CISC-L2-000210", "disabled switch ports", []string{"inactive VLAN", "not in use"},
		idPair{"V-220667", "SV-220667r991904_rule"},
		idPair{"V-220641", "SV-220641r991848_rule"},
		idPair{"V-220690", "SV-220690r991946_rule"},
		evalUnusedPorts)
	allThree("CISC-L2-000220", "default VLAN", []string{"default VLAN", "show vlan"},
		idPair{"V-220668", "SV-220668r991905_rule"},
		idPair{"V-220642", "SV-220642r991849_rule"},
		idPair{"V-220691", "SV-220691r991947_rule"},
		evalDefaultVLANAccess)
	register(checkSpec{
		Version: "CISC-L2-000230", Title: "default VLAN",
		Common: []string{"default VLAN"},
		Phrases: map[string][]string{
			"Cisco_IOS_XE_Switch_L2S_STIG": {"show interfaces trunk", "default VLAN"},
			"Cisco_IOS_Switch_L2S_STIG":    {"show interfaces trunk", "default VLAN"},
			"Cisco_NX-OS_Switch_L2S_STIG":  {"default VLAN", "trunk"},
		},
		Eval: evalPruneDefaultVLAN,
		IDs: map[string]idPair{
			"Cisco_IOS_XE_Switch_L2S_STIG": {"V-220669", "SV-220669r991906_rule"},
			"Cisco_IOS_Switch_L2S_STIG":    {"V-220643", "SV-220643r991850_rule"},
			"Cisco_NX-OS_Switch_L2S_STIG":  {"V-220692", "SV-220692r991948_rule"},
		},
	})
	register(checkSpec{
		Version: "CISC-L2-000240", Title: "default VLAN",
		Common: []string{"default VLAN"},
		Eval:   evalManagementVLAN,
		IDs: map[string]idPair{
			"Cisco_IOS_XE_Switch_L2S_STIG": {"V-220670", "SV-220670r991907_rule"},
			"Cisco_IOS_Switch_L2S_STIG":    {"V-220644", "SV-220644r991852_rule"},
			"Cisco_NX-OS_Switch_L2S_STIG":  {"V-220693", "SV-220693r991949_rule"},
		},
	})
	allThree("CISC-L2-000250", "user-facing", []string{"user-facing", "trunk"},
		idPair{"V-220671", "SV-220671r991908_rule"},
		idPair{"V-220645", "SV-220645r991853_rule"},
		idPair{"V-220694", "SV-220694r991951_rule"},
		evalUserPortsAccess)
	allThree("CISC-L2-000260", "native VLAN", []string{"native vlan", "default VLAN"},
		idPair{"V-220672", "SV-220672r991909_rule"},
		idPair{"V-220646", "SV-220646r991854_rule"},
		idPair{"V-220695", "SV-220695r991952_rule"},
		evalNativeVLAN)
	allThree("CISC-L2-000270", "native VLAN", []string{"native VLAN", "access switch ports"},
		idPair{"V-220673", "SV-220673r991910_rule"},
		idPair{"V-220647", "SV-220647r991855_rule"},
		idPair{"V-220696", "SV-220696r991953_rule"},
		evalAccessNotNative)
}

func evalVTP(ctx checkContext) (string, string, string) {
	switch {
	case ctx.Config.Has("vtp mode off") || ctx.Config.Has("no feature vtp"):
		return pass("VTP mode is off in the saved configuration, so VTP message authentication is not required by this check.")
	case ctx.Config.HasPrefix("vtp mode "):
		if ctx.Config.HasPrefix("vtp password ") {
			return pass("VTP is not off and a vtp password command is present. The password value was not copied.")
		}
		mode := "a non-off mode"
		for _, candidate := range []string{"vtp mode transparent", "vtp mode server", "vtp mode client"} {
			if ctx.Config.Has(candidate) {
				mode = candidate
			}
		}
		return fail("VTP is configured as " + mode + " and no vtp password command is present. This check requires a password whenever the mode is not off.")
	default:
		return manual("No vtp mode command is in the snapshot. This check calls for show vtp status before a mode of off can be assumed.")
	}
}

func evalRootGuard(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var targets []string
	var missing []string
	for _, port := range ctx.Config.Switchports() {
		role := ctx.Roles.ByName[port.InterfaceName()]
		if role.Role != "access-switch" {
			continue
		}
		targets = append(targets, port.InterfaceName())
		if !port.Has("spanning-tree guard root") {
			missing = append(missing, port.InterfaceName())
		}
	}
	if len(targets) == 0 {
		return na("The port-role table has no access-switch ports, so Root Guard is not required by this check.")
	}
	if len(missing) > 0 {
		return fail("Root Guard is missing on access-switch ports " + joinNames(missing) + ".")
	}
	return pass("Root Guard is configured on every port the role table marks as connected to an access-layer switch.")
}

func evalBPDUGuard(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var missing []string
	users := 0
	for _, port := range ctx.Config.Switchports() {
		role := ctx.Roles.ByName[port.InterfaceName()]
		if !role.UserFacing {
			continue
		}
		users++
		if !port.Has("spanning-tree bpduguard enable") {
			missing = append(missing, port.InterfaceName())
		}
	}
	if users == 0 {
		return na("The port-role table has no user-facing ports, so per-port BPDU Guard is not required by this check.")
	}
	if len(missing) > 0 {
		return fail("BPDU Guard is missing on user-facing ports " + joinNames(missing) + ". A global default was not accepted in place of the interface command this check shows.")
	}
	return pass("Every user-facing port has spanning-tree bpduguard enable.")
}

func evalLoopGuard(ctx checkContext) (string, string, string) {
	if ctx.Config.anyBlockHas("spanning-tree guard none") {
		return manual("An interface sets spanning-tree guard none, which disables Loop Guard on that port. The global command alone is not a pass.")
	}
	if ctx.Config.Has("spanning-tree loopguard default") && !ctx.Config.Has("no spanning-tree loopguard default") {
		return pass("Global spanning-tree loopguard default is present and no interface disables Loop Guard with spanning-tree guard none. Operational STP state was not observed.")
	}
	if ctx.Config.Has("no spanning-tree loopguard default") && !ctx.Config.anyBlockHas("spanning-tree guard loop") {
		return fail("STP Loop Guard is explicitly disabled with no spanning-tree loopguard default, and no interface enables spanning-tree guard loop. This finding assumes the saved configuration is the one under review.")
	}
	if ctx.Config.anyBlockHas("spanning-tree guard loop") {
		return manual("Loop Guard is enabled on at least one interface and the global default is absent. Coverage of the remaining STP ports was not decided.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Global Loop Guard is not configured."))
	}
	return fail("STP Loop Guard is not configured. The saved configuration has neither spanning-tree loopguard default nor a per-interface spanning-tree guard loop command.")
}

func evalUUFB(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var missing []string
	access := 0
	for _, port := range ctx.Config.Switchports() {
		role := ctx.Roles.ByName[port.InterfaceName()]
		if role.Role != "user" && role.Role != "unused" {
			continue
		}
		if !port.Has("switchport mode access") && !port.HasPrefix("switchport access vlan ") {
			continue
		}
		access++
		if !port.Has("switchport block unicast") {
			missing = append(missing, port.InterfaceName())
		}
	}
	if access == 0 {
		return na("The port-role table has no user or unused access ports for UUFB.")
	}
	if len(missing) > 0 {
		return fail("Unknown unicast flood blocking is missing on access ports " + joinNames(missing) + ".")
	}
	return pass("Every user and unused access port has switchport block unicast.")
}

func evalDHCPSnooping(ctx checkContext) (string, string, string) {
	vlans, why, ok := userVLANs(ctx)
	if !ok {
		return manual(why)
	}
	if len(vlans) == 0 {
		return na("The port-role table has no user-facing VLANs, so DHCP snooping has no user VLAN to cover.")
	}
	if !ctx.Config.Has("ip dhcp snooping") && !ctx.Config.Has("feature dhcp") {
		if !ctx.Config.Complete(ctx.Family) {
			return manual(incomplete(ctx.Family, "DHCP snooping is not enabled."))
		}
		return fail("DHCP snooping is not enabled with ip dhcp snooping.")
	}
	if !ctx.Config.Has("ip dhcp snooping") {
		return fail("DHCP snooping feature state is incomplete: ip dhcp snooping is not present.")
	}
	covered, parsed := vlanCommandSet(ctx.Config, "ip dhcp snooping vlan ")
	if !parsed && ctx.Config.HasPrefix("ip dhcp snooping vlan ") {
		return manual("The ip dhcp snooping vlan list could not be parsed.")
	}
	var missing []int
	for vlan := range vlans {
		if !covered[vlan] {
			missing = append(missing, vlan)
		}
	}
	if len(missing) > 0 {
		return fail("DHCP snooping is not enabled for user VLAN " + joinInts(missing) + ".")
	}
	return pass("ip dhcp snooping is enabled and covers every user VLAN named by the port-role table.")
}

func evalIPSourceGuard(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var missing []string
	users := 0
	for _, port := range ctx.Config.Switchports() {
		if !ctx.Roles.ByName[port.InterfaceName()].UserFacing {
			continue
		}
		users++
		if !port.HasPrefix("ip verify source") {
			missing = append(missing, port.InterfaceName())
		}
	}
	if users == 0 {
		return na("The port-role table has no user-facing ports for IP Source Guard.")
	}
	if len(missing) > 0 {
		return fail("IP Source Guard is missing on user-facing ports " + joinNames(missing) + ".")
	}
	return pass("Every user-facing port has an ip verify source command. The DHCP snooping binding database was not inspected.")
}

func evalDAI(ctx checkContext) (string, string, string) {
	vlans, why, ok := userVLANs(ctx)
	if !ok {
		return manual(why)
	}
	if len(vlans) == 0 {
		return na("The port-role table has no user-facing VLANs, so DAI has no user VLAN to cover.")
	}
	covered, parsed := vlanCommandSet(ctx.Config, "ip arp inspection vlan ")
	if !parsed {
		if ctx.Config.HasPrefix("ip arp inspection vlan ") {
			return manual("The ip arp inspection vlan list could not be parsed.")
		}
		if !ctx.Config.Complete(ctx.Family) {
			return manual(incomplete(ctx.Family, "DAI is not configured."))
		}
		return fail("Dynamic ARP Inspection is not configured for the user VLANs.")
	}
	var missing []int
	for vlan := range vlans {
		if !covered[vlan] {
			missing = append(missing, vlan)
		}
	}
	if len(missing) > 0 {
		return fail("DAI is not enabled for user VLAN " + joinInts(missing) + ".")
	}
	return pass("ip arp inspection vlan covers every user VLAN named by the port-role table. The DHCP snooping binding database was not inspected.")
}

func evalStormControl(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var missing []string
	users := 0
	for _, port := range ctx.Config.Switchports() {
		if !ctx.Roles.ByName[port.InterfaceName()].UserFacing {
			continue
		}
		users++
		if !port.HasPrefix("storm-control broadcast") {
			missing = append(missing, port.InterfaceName())
		}
	}
	if users == 0 {
		return na("The port-role table has no user-facing ports for storm control.")
	}
	if len(missing) > 0 {
		return fail("Broadcast storm control is missing on user-facing ports " + joinNames(missing) + ".")
	}
	return pass("Every user-facing port has a storm-control broadcast command. Threshold values were not judged.")
}

func evalIGMP(ctx checkContext) (string, string, string) {
	if ctx.Config.Has("no ip igmp snooping") || ctx.Config.HasPrefix("no ip igmp snooping vlan ") {
		return fail("IGMP snooping is disabled globally or for a VLAN.")
	}
	if ctx.Config.Has("ip igmp snooping") || ctx.Config.Complete(ctx.Family) {
		return pass("IGMP snooping is not disabled. The negative commands no ip igmp snooping and no ip igmp snooping vlan are absent. MLD snooping was not separately confirmed.")
	}
	return manual(incomplete(ctx.Family, "IGMP snooping commands were not seen."))
}

func evalRapidSTP(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why + " Rapid STP was not marked Not a Finding from the mode command alone.")
	}
	spans := false
	for _, role := range ctx.Roles.ByName {
		if role.Role == "uplink" || role.Role == "access-switch" {
			spans = true
		}
	}
	if !spans {
		return na("The port-role table has no uplink or access-switch port, so the check's condition that STP is required is not met.")
	}
	rapid := ctx.Config.Has("spanning-tree mode rapid-pvst")
	mst := ctx.Config.Has("spanning-tree mode mst")
	pvst := ctx.Config.Has("spanning-tree mode pvst")
	if ctx.Config.Has("no spanning-tree mode") || (rapid && mst) || ((rapid || mst) && pvst) {
		return manual("Spanning-tree mode commands conflict, so Rapid STP was not decided.")
	}
	if rapid || mst {
		return pass("The port-role table records a multi-switch link and the global mode is Rapid STP or MSTP. Topology beyond the role table was not observed.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Rapid STP or MSTP is not configured."))
	}
	return fail("The port-role table records a multi-switch link and the saved configuration does not select spanning-tree mode rapid-pvst or mst.")
}

func evalUDLD(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var fiber []string
	var missing []string
	for _, port := range ctx.Config.Switchports() {
		role := ctx.Roles.ByName[port.InterfaceName()]
		if !role.Fiber {
			continue
		}
		fiber = append(fiber, port.InterfaceName())
		if !ctx.Config.Has("udld enable") && !port.Has("udld port") && !port.HasPrefix("udld port") {
			missing = append(missing, port.InterfaceName())
		}
	}
	if len(fiber) == 0 {
		return na("The port-role table records no fiber interfaces, so UDLD is not required by this check.")
	}
	if len(missing) > 0 {
		return fail("UDLD is not enabled globally or on fiber ports " + joinNames(missing) + ".")
	}
	return pass("UDLD is enabled for every port the role table marks as fiber.")
}

func evalTrunkNegotiation(ctx checkContext) (string, string, string) {
	ports := ctx.Config.Switchports()
	if len(ports) == 0 {
		return manual("No switch interfaces were found, so trunk negotiation was not decided.")
	}
	var negotiating []string
	for _, port := range ports {
		switch {
		case port.Has("switchport nonegotiate"):
			continue
		case port.Has("switchport mode access"):
			continue
		case port.Has("switchport mode trunk") || port.Has("switchport mode dynamic auto") || port.Has("switchport mode dynamic desirable") || port.HasPrefix("switchport mode dynamic"):
			negotiating = append(negotiating, port.InterfaceName())
		default:
			if ctx.Config.Complete(ctx.Family) {
				negotiating = append(negotiating, port.InterfaceName())
			} else {
				return manual(incomplete(ctx.Family, "Some interfaces have no explicit switchport mode."))
			}
		}
	}
	if len(negotiating) > 0 {
		return fail("Trunk negotiation is not disabled on " + joinNames(negotiating) + ". Trunk ports need switchport nonegotiate; other ports need an access mode or nonegotiate.")
	}
	return pass("Every switch port is access mode or has switchport nonegotiate. Live show interfaces switchport output was not collected.")
}

func evalUnusedPorts(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var unused []*Block
	for _, port := range ctx.Config.Switchports() {
		if ctx.Roles.ByName[port.InterfaceName()].Role == "unused" {
			unused = append(unused, port)
		}
	}
	if len(unused) == 0 {
		return na("The port-role table has no unused ports.")
	}
	trunks, trunksOK := trunkAllowed(ctx.Config)
	if !trunksOK {
		return manual("A trunk allowed-VLAN list could not be parsed, so unused-VLAN pruning was not decided.")
	}
	var bad []string
	for _, port := range unused {
		vlan, ok := accessVLAN(port)
		if !port.Has("shutdown") || !ok || vlan == 1 || trunks[vlan] {
			bad = append(bad, port.InterfaceName())
		}
	}
	if len(bad) > 0 {
		return fail("Unused ports " + joinNames(bad) + " are not shut down in a non-default VLAN that is absent from every trunk allow list.")
	}
	return pass("Every unused port is shut down in a non-default VLAN that is not permitted on the parsed trunks.")
}

func evalDefaultVLANAccess(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var bad []string
	access := 0
	for _, port := range ctx.Config.Switchports() {
		role := ctx.Roles.ByName[port.InterfaceName()]
		if role.Role != "user" && role.Role != "unused" {
			continue
		}
		vlan, ok := accessVLAN(port)
		if !ok {
			return manual("An access VLAN could not be read for " + port.InterfaceName() + ".")
		}
		access++
		if vlan == 1 {
			bad = append(bad, port.InterfaceName())
		}
	}
	if access == 0 {
		return na("The port-role table has no user or unused access ports.")
	}
	if len(bad) > 0 {
		return fail("Access ports " + joinNames(bad) + " are assigned to default VLAN 1.")
	}
	return pass("No user or unused access port is assigned to VLAN 1. show vlan was not collected.")
}

func evalPruneDefaultVLAN(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var trunks []*Block
	for _, port := range ctx.Config.Switchports() {
		if port.Has("switchport mode trunk") {
			trunks = append(trunks, port)
		}
	}
	if len(trunks) == 0 {
		return na("The snapshot has no switchport mode trunk interfaces.")
	}
	var bad []string
	for _, port := range trunks {
		allowed, explicit, ok := oneTrunkAllowed(port)
		if !ok || !explicit {
			return manual("Trunk " + port.InterfaceName() + " has no simple allowed-VLAN list, so pruning of VLAN 1 was not decided.")
		}
		if allowed[1] {
			bad = append(bad, port.InterfaceName())
		}
	}
	if len(bad) > 0 {
		return fail("Default VLAN 1 remains on trunk allow lists for " + joinNames(bad) + ".")
	}
	return pass("No parsed trunk allow list includes VLAN 1. Whether each trunk should carry other VLANs was not judged.")
}

func evalManagementVLAN(ctx checkContext) (string, string, string) {
	vlan1 := ctx.Config.Interface("Vlan1")
	if vlan1 == nil {
		vlan1 = ctx.Config.Interface("vlan1")
	}
	if vlan1 != nil && vlan1.HasPrefix("ip address ") && !vlan1.Has("shutdown") {
		return fail("Interface VLAN 1 has an IP address and is not shut down, so the default VLAN is available for management.")
	}
	managed := false
	for _, block := range ctx.Config.Blocks {
		name := block.InterfaceName()
		if name == "" || name == "Vlan1" || name == "vlan1" {
			continue
		}
		if block.HasPrefix("ip address ") && !strings.HasPrefix(block.FirstPrefix("ip address "), "no ip address") {
			managed = true
		}
	}
	if !managed {
		return manual("No management IP address was found on a non-default interface, so management VLAN use was not decided.")
	}
	return pass("A management IP address is present on an interface other than VLAN 1, and VLAN 1 is not an active addressed interface.")
}

func evalUserPortsAccess(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	var bad []string
	users := 0
	for _, port := range ctx.Config.Switchports() {
		if !ctx.Roles.ByName[port.InterfaceName()].UserFacing {
			continue
		}
		users++
		if port.Has("switchport mode trunk") || !port.Has("switchport mode access") {
			bad = append(bad, port.InterfaceName())
		}
	}
	if users == 0 {
		return na("The port-role table has no user-facing ports.")
	}
	if len(bad) > 0 {
		return fail("User-facing ports " + joinNames(bad) + " are not configured as access ports.")
	}
	return pass("Every user-facing port is switchport mode access.")
}

func evalNativeVLAN(ctx checkContext) (string, string, string) {
	var trunks []*Block
	for _, port := range ctx.Config.Switchports() {
		if port.Has("switchport mode trunk") {
			trunks = append(trunks, port)
		}
	}
	if len(trunks) == 0 {
		return na("The snapshot has no switchport mode trunk interfaces.")
	}
	var bad []string
	for _, port := range trunks {
		native, ok := nativeVLAN(port)
		if !ok || native == 1 {
			bad = append(bad, port.InterfaceName())
		}
	}
	if len(bad) > 0 {
		return fail("Trunk native VLAN is missing or is VLAN 1 on " + joinNames(bad) + ".")
	}
	return pass("Every trunk has a native VLAN other than VLAN 1.")
}

func evalAccessNotNative(ctx checkContext) (string, string, string) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return manual(why)
	}
	natives := map[int]bool{}
	for _, port := range ctx.Config.Switchports() {
		if !port.Has("switchport mode trunk") {
			continue
		}
		native, ok := nativeVLAN(port)
		if !ok {
			return manual("Trunk " + port.InterfaceName() + " has no native VLAN, so access-port comparison was not decided.")
		}
		natives[native] = true
	}
	if len(natives) == 0 {
		return na("The snapshot has no trunks, so no access port can share a trunk native VLAN.")
	}
	var bad []string
	for _, port := range ctx.Config.Switchports() {
		role := ctx.Roles.ByName[port.InterfaceName()]
		if role.Role != "user" && role.Role != "unused" {
			continue
		}
		vlan, ok := accessVLAN(port)
		if !ok {
			return manual("An access VLAN could not be read for " + port.InterfaceName() + ".")
		}
		if natives[vlan] {
			bad = append(bad, port.InterfaceName())
		}
	}
	if len(bad) > 0 {
		return fail("Access ports " + joinNames(bad) + " use a VLAN that is also a trunk native VLAN.")
	}
	return pass("No user or unused access VLAN matches a trunk native VLAN.")
}

func userVLANs(ctx checkContext) (map[int]bool, string, bool) {
	ready, why := roleGate(ctx.Config, ctx.Roles)
	if !ready {
		return nil, why, false
	}
	out := map[int]bool{}
	for _, port := range ctx.Config.Switchports() {
		if !ctx.Roles.ByName[port.InterfaceName()].UserFacing {
			continue
		}
		if vlan, ok := accessVLAN(port); ok {
			out[vlan] = true
		}
		if line := port.FirstPrefix("switchport voice vlan "); line != "" {
			set, parsed := ParseVLANs(strings.TrimPrefix(line, "switchport voice vlan "))
			if !parsed || len(set) != 1 {
				return nil, "Voice VLAN on " + port.InterfaceName() + " could not be parsed.", false
			}
			for n := range set {
				out[n] = true
			}
		}
	}
	return out, "", true
}

func accessVLAN(port *Block) (int, bool) {
	if line := port.FirstPrefix("switchport access vlan "); line != "" {
		set, ok := ParseVLANs(strings.TrimPrefix(line, "switchport access vlan "))
		if !ok || len(set) != 1 {
			return 0, false
		}
		for n := range set {
			return n, true
		}
	}
	if port.Has("switchport mode access") {
		return 1, true
	}
	return 0, false
}

func nativeVLAN(port *Block) (int, bool) {
	line := port.FirstPrefix("switchport trunk native vlan ")
	if line == "" {
		return 1, false
	}
	set, ok := ParseVLANs(strings.TrimPrefix(line, "switchport trunk native vlan "))
	if !ok || len(set) != 1 {
		return 0, false
	}
	for n := range set {
		return n, true
	}
	return 0, false
}

func oneTrunkAllowed(port *Block) (map[int]bool, bool, bool) {
	line := port.FirstPrefix("switchport trunk allowed vlan ")
	if line == "" {
		return nil, false, true
	}
	set, ok := ParseVLANs(strings.TrimPrefix(line, "switchport trunk allowed vlan "))
	if !ok {
		return nil, false, false
	}
	return set, true, true
}

func trunkAllowed(cfg *Config) (map[int]bool, bool) {
	combined := map[int]bool{}
	for _, port := range cfg.Switchports() {
		if !port.Has("switchport mode trunk") {
			continue
		}
		allowed, explicit, ok := oneTrunkAllowed(port)
		if !ok {
			return nil, false
		}
		if !explicit {
			return nil, false
		}
		for vlan := range allowed {
			combined[vlan] = true
		}
	}
	return combined, true
}

func joinInts(values []int) string {
	sortInts(values)
	parts := make([]string, len(values))
	for i, n := range values {
		parts[i] = itoa(n)
	}
	return strings.Join(parts, ", ")
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
