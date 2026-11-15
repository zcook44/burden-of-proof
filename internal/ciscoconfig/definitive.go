package ciscoconfig

import (
	"strconv"
	"strings"
)

func registerDefinitive() {
	xeSW := "Cisco_IOS_XE_Switch_NDM_STIG"
	iosSW := "Cisco_IOS_Switch_NDM_STIG"
	xeRT := "Cisco_IOS-XE_Router_NDM_STIG"
	iosRT := "Cisco_IOS_Router_NDM_STIG"
	four := func(version, title string, phrases []string, xeS, iosS, xeR, iosR idPair, eval func(checkContext) (string, string, string)) {
		register(checkSpec{Version: version, Title: title, Common: phrases, Eval: eval, IDs: map[string]idPair{
			xeSW: xeS, iosSW: iosS, xeRT: xeR, iosRT: iosR,
		}})
	}
	four("CISC-ND-000150", "three consecutive invalid logon", []string{"login block-for", "attempts 3", "this is a finding"},
		idPair{"V-220524", "SV-220524r960840_rule"}, idPair{"V-220576", "SV-220576r960840_rule"},
		idPair{"V-215813", "SV-215813r960840_rule"}, idPair{"V-215668", "SV-215668r960840_rule"}, evalLoginLockout)
	four("CISC-ND-000380", "unauthorized modification", []string{"logging persistent", "not applicable"},
		idPair{"V-220531", "SV-220531r960933_rule"}, idPair{"V-220583", "SV-220583r960933_rule"},
		idPair{"V-215820", "SV-215820r960933_rule"}, idPair{"V-215675", "SV-215675r960933_rule"}, evalPersistentLogging)
	four("CISC-ND-000390", "unauthorized deletion", []string{"logging persistent", "not applicable"},
		idPair{"V-220532", "SV-220532r960936_rule"}, idPair{"V-220584", "SV-220584r960936_rule"},
		idPair{"V-215821", "SV-215821r960936_rule"}, idPair{"V-215676", "SV-215676r960936_rule"}, evalPersistentLogging)
	register(checkSpec{Version: "CISC-ND-000460", Title: "software resident", Common: []string{"logging persistent", "not applicable"}, Eval: evalPersistentLogging,
		IDs: map[string]idPair{xeSW: {"V-220533", "SV-220533r960960_rule"}, iosSW: {"V-220585", "SV-220585r960960_rule"}}})
	four("CISC-ND-000470", "unnecessary", []string{"ip http server", "this is a finding"},
		idPair{"V-220534", "SV-220534r1043177_rule"}, idPair{"V-220586", "SV-220586r1043177_rule"},
		idPair{"V-215823", "SV-215823r1043177_rule"}, idPair{"V-215678", "SV-215678r1043177_rule"}, evalInsecureServices)
	four("CISC-ND-000490", "account of last resort", []string{"common-criteria-policy", "this is a finding"},
		idPair{"V-220535", "SV-220535r1051115_rule"}, idPair{"V-220587", "SV-220587r1051115_rule"},
		idPair{"V-215824", "SV-215824r1051115_rule"}, idPair{"V-215679", "SV-215679r1051115_rule"}, evalLastResortAccount)
	four("CISC-ND-000550", "minimum 15-character", []string{"min-length 15", "this is a finding"},
		idPair{"V-220537", "SV-220537r991912_rule"}, idPair{"V-220589", "SV-220589r1015280_rule"},
		idPair{"V-215826", "SV-215826r1015288_rule"}, idPair{"V-215681", "SV-215681r991820_rule"}, evalPasswordMinimum)
	four("CISC-ND-000570", "at least one uppercase", []string{"upper-case 1", "this is a finding"},
		idPair{"V-220538", "SV-220538r991915_rule"}, idPair{"V-220590", "SV-220590r1015281_rule"},
		idPair{"V-215827", "SV-215827r1015289_rule"}, idPair{"V-215682", "SV-215682r991823_rule"}, evalPasswordUpper)
	four("CISC-ND-000580", "at least one lowercase", []string{"lower-case 1", "this is a finding"},
		idPair{"V-220539", "SV-220539r991918_rule"}, idPair{"V-220591", "SV-220591r1015282_rule"},
		idPair{"V-215828", "SV-215828r1015290_rule"}, idPair{"V-215683", "SV-215683r991826_rule"}, evalPasswordLower)
	four("CISC-ND-000590", "at least one numeric", []string{"numeric-count 1", "this is a finding"},
		idPair{"V-220540", "SV-220540r991919_rule"}, idPair{"V-220592", "SV-220592r1015283_rule"},
		idPair{"V-215829", "SV-215829r1015291_rule"}, idPair{"V-215684", "SV-215684r991827_rule"}, evalPasswordNumeric)
	four("CISC-ND-000600", "at least one special", []string{"special-case 1", "this is a finding"},
		idPair{"V-220541", "SV-220541r991920_rule"}, idPair{"V-220593", "SV-220593r1015284_rule"},
		idPair{"V-215830", "SV-215830r1015292_rule"}, idPair{"V-215685", "SV-215685r991828_rule"}, evalPasswordSpecial)
	four("CISC-ND-000610", "characters are changed", []string{"char-changes 8", "this is a finding"},
		idPair{"V-220542", "SV-220542r1043189_rule"}, idPair{"V-220594", "SV-220594r1043189_rule"},
		idPair{"V-215831", "SV-215831r1043189_rule"}, idPair{"V-215686", "SV-215686r1043189_rule"}, evalPasswordChanges)
	four("CISC-ND-001000", "audit failure events", []string{"logging trap", "informational"},
		idPair{"V-220548", "SV-220548r991923_rule"}, idPair{"V-220600", "SV-220600r991868_rule"},
		idPair{"V-215837", "SV-215837r991886_rule"}, idPair{"V-215692", "SV-215692r991831_rule"}, evalLoggingTrap)

	register(checkSpec{
		Version: "CISC-L2-000020", Title: "network-connected endpoint devices before establishing",
		Common: []string{"802.1x", "MAB"}, Eval: evalDot1x,
		IDs: map[string]idPair{
			"Cisco_IOS_XE_Switch_L2S_STIG": {"V-220649", "SV-220649r863283_rule"},
			"Cisco_IOS_Switch_L2S_STIG":    {"V-220623", "SV-220623r863275_rule"},
		},
	})
	register(checkSpec{
		Version: "CISC-L2-000040", Title: "excess bandwidth",
		Common: []string{"If quality of service (QoS) has not been enabled, this is a finding."}, Eval: evalQoSEnabled,
		IDs: map[string]idPair{"Cisco_IOS_XE_Switch_L2S_STIG": {"V-220651", "SV-220651r1107171_rule"}},
	})

	xeSWR := "Cisco_IOS_XE_Switch_RTR_STIG"
	iosSWR := "Cisco_IOS_Switch_RTR_STIG"
	xeRTR := "Cisco_IOS-XE_Router_RTR_STIG"
	iosRTR := "Cisco_IOS_Router_RTR_STIG"
	register(checkSpec{Version: "CISC-RT-000160", Title: "directed broadcast", Common: []string{"ip directed-broadcast", "this is a finding"}, Eval: evalDirectedBroadcast,
		IDs: map[string]idPair{
			xeSWR: {"V-220999", "SV-220999r856404_rule"}, iosSWR: {"V-220432", "SV-220432r856234_rule"},
			xeRTR: {"V-216654", "SV-216654r855815_rule"}, iosRTR: {"V-216564", "SV-216564r856183_rule"},
		}})
	register(checkSpec{Version: "CISC-RT-000235", Title: "Cisco Express Forwarding", Common: []string{"ip cef", "this is a finding"}, Eval: evalCEF,
		IDs: map[string]idPair{
			xeSWR: {"V-237750", "SV-237750r648776_rule"}, iosSWR: {"V-237749", "SV-237749r648775_rule"},
			xeRTR: {"V-229031", "SV-229031r878127_rule"}, iosRTR: {"V-229030", "SV-229030r878127_rule"},
		}})
	register(checkSpec{Version: "CISC-RT-000237", Title: "Site Local", Common: []string{"this is a finding"}, Eval: evalSiteLocal,
		IDs: map[string]idPair{
			xeSWR: {"V-237756", "SV-237756r999760_rule"}, iosSWR: {"V-237755", "SV-237755r999760_rule"},
			xeRTR: {"V-230042", "SV-230042r647455_rule"}, iosRTR: {"V-230041", "SV-230041r532998_rule"},
			"Cisco_NX-OS_Switch_RTR_STIG":  {"V-237757", "SV-237757r999761_rule"},
			"Cisco_IOS-XR_Router_RTR_STIG": {"V-230043", "SV-230043r533001_rule"},
		}})
	register(checkSpec{Version: "CISC-RT-000620", Title: "TTL Propagation", Common: []string{"no mpls ip propagate-ttl", "this is a finding"}, Eval: evalMPLSTTL,
		IDs: map[string]idPair{
			xeSWR: {"V-221036", "SV-221036r622190_rule"},
			xeRTR: {"V-216700", "SV-216700r531086_rule"}, iosRTR: {"V-216610", "SV-216610r531085_rule"},
		}})
	register(checkSpec{
		Version: "CISC-ND-001280", Title: "starting and ending time for administrator access",
		Common: []string{"logging level authpri 6", "If the switch is not configured to generate log records showing starting and ending time for administrator access, this is a finding."},
		Eval:   evalAdminSessionLogging,
		IDs:    map[string]idPair{"Cisco_NX-OS_Switch_NDM_STIG": {"V-220510", "SV-220510r961830_rule"}},
	})
	extendNXCommandChecks()
}

func evalLoginLockout(ctx checkContext) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXLoginAttempts(ctx)
	}
	attempts, ok := loginAttempts(ctx.Config)
	if !ok {
		if !ctx.Config.Complete(ctx.Family) {
			return manual(incomplete(ctx.Family, "login block-for was not found."))
		}
		return fail("login block-for attempts 3 is not configured, so three consecutive invalid logons are not blocked.")
	}
	if attempts > 3 {
		return fail("login block-for allows more than three invalid attempts, so it does not enforce the required limit.")
	}
	return pass("login block-for limits invalid attempts to three or fewer. The block duration was not judged.")
}

func loginAttempts(cfg *Config) (int, bool) {
	for line := range cfg.Globals {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "login" && fields[1] == "block-for" && fields[3] == "attempts" {
			n, err := strconv.Atoi(fields[4])
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func evalPersistentLogging(ctx checkContext) (string, string, string) {
	if !ctx.Config.HasPrefix("logging persistent") {
		return na("logging persistent is not configured, and this check says the requirement is not applicable unless persistent logging is enabled.")
	}
	for line := range ctx.Config.Globals {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "file" && fields[1] == "privilege" {
			level, err := strconv.Atoi(fields[2])
			if err == nil && level != 15 {
				return fail("Persistent logging is enabled and file privilege is " + fields[2] + ", which is not the default of 15.")
			}
		}
	}
	return pass("Persistent logging is enabled and file privilege is not set below the default of 15.")
}

func evalInsecureServices(ctx checkContext) (string, string, string) {
	forbidden := []string{
		"boot network", "ip boot server", "ip bootp server", "ip dns server", "ip identd", "ip finger",
		"ip http server", "ip rcmd rcp-enable", "ip rcmd rsh-enable", "service config", "service finger",
		"service tcp-small-servers", "service udp-small-servers", "service pad",
	}
	var enabled []string
	for _, command := range forbidden {
		if ctx.Config.Has(command) {
			enabled = append(enabled, command)
		}
	}
	if len(enabled) > 0 {
		return fail("Insecure example services are enabled: " + joinNames(enabled) + ". service call-home was not treated as a finding because the check allows it for legacy Smart Licensing.")
	}
	return manual("None of the check's example insecure services are enabled. The list is not exhaustive, so that absence is not a pass. Confirm no other unnecessary service is enabled, then set the status in this device's tailoring file.")
}

func evalLastResortAccount(ctx checkContext) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXLastResort(ctx)
	}
	var accounts []string
	for line := range ctx.Config.Globals {
		if strings.HasPrefix(line, "username ") {
			accounts = append(accounts, line)
		}
	}
	if len(accounts) != 1 {
		if !ctx.Config.Complete(ctx.Family) && len(accounts) == 0 {
			return manual(incomplete(ctx.Family, "No local username was found."))
		}
		return fail("The configuration has " + itoa(len(accounts)) + " username commands. This check allows one local account of last resort.")
	}
	if !strings.Contains(accounts[0], "common-criteria-policy") {
		return fail("The single local account does not reference a common-criteria-policy. The account name was not copied.")
	}
	if !remoteThenLocal(ctx.Config) {
		return fail("aaa authentication login does not place local after a TACACS or RADIUS method.")
	}
	return pass("One local account references a common-criteria policy, and local authentication follows a TACACS or RADIUS method. The password was not copied.")
}

func remoteThenLocal(cfg *Config) bool {
	groups := map[string]bool{}
	for _, block := range cfg.Blocks {
		fields := strings.Fields(block.Header)
		if len(fields) == 5 && fields[0] == "aaa" && fields[1] == "group" && fields[2] == "server" && (fields[3] == "tacacs+" || fields[3] == "radius") {
			groups[fields[4]] = true
		}
	}
	for line := range cfg.Globals {
		if !strings.HasPrefix(line, "aaa authentication login ") || !strings.Contains(line, " local") {
			continue
		}
		localAt := strings.LastIndex(line, " local")
		remoteAt := -1
		for _, word := range []string{"tacacs", "radius"} {
			if at := strings.Index(line, word); at >= 0 && (remoteAt < 0 || at < remoteAt) {
				remoteAt = at
			}
		}
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "group" && i+1 < len(fields) && groups[fields[i+1]] {
				at := strings.Index(line, fields[i+1])
				if remoteAt < 0 || at < remoteAt {
					remoteAt = at
				}
			}
		}
		if remoteAt >= 0 && remoteAt < localAt {
			return true
		}
	}
	return false
}

func evalPasswordMinimum(ctx checkContext) (string, string, string) {
	return passwordSetting(ctx, "min-length", 15, "minimum length of 15")
}
func evalPasswordUpper(ctx checkContext) (string, string, string) {
	return passwordSetting(ctx, "upper-case", 1, "at least one uppercase character")
}
func evalPasswordLower(ctx checkContext) (string, string, string) {
	return passwordSetting(ctx, "lower-case", 1, "at least one lowercase character")
}
func evalPasswordNumeric(ctx checkContext) (string, string, string) {
	return passwordSetting(ctx, "numeric-count", 1, "at least one numeric character")
}
func evalPasswordSpecial(ctx checkContext) (string, string, string) {
	return passwordSetting(ctx, "special-case", 1, "at least one special character")
}
func evalPasswordChanges(ctx checkContext) (string, string, string) {
	return passwordSetting(ctx, "char-changes", 8, "at least eight changed characters")
}

func passwordSetting(ctx checkContext, name string, minimum int, label string) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXPasswordStrength(ctx)
	}
	if commonCriteriaAtLeast(ctx.Config, name, minimum) {
		return pass("An aaa common-criteria policy sets " + name + " to the required value or stricter. security passwords min-length was not accepted as a substitute.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "No aaa common-criteria policy sets "+name+"."))
	}
	return fail("No aaa common-criteria policy sets " + name + " for " + label + ". A security passwords command was not accepted as a substitute.")
}

func commonCriteriaAtLeast(cfg *Config, name string, minimum int) bool {
	for _, block := range cfg.Blocks {
		if !strings.HasPrefix(block.Header, "aaa common-criteria policy ") {
			continue
		}
		for line := range block.Set {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == name {
				value, err := strconv.Atoi(fields[1])
				if err == nil && value >= minimum {
					return true
				}
			}
		}
	}
	return false
}

func evalLoggingTrap(ctx checkContext) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXAuditLogServers(ctx)
	}
	for line := range ctx.Config.Globals {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "logging" && fields[1] == "trap" {
			if trapCoversAuditFailures(fields[2]) {
				return pass("logging trap " + fields[2] + " is critical or a more verbose level, which covers audit failure messages. Informational is the default when the command is absent.")
			}
			return fail("logging trap " + fields[2] + " is less verbose than critical, so it does not alert on all audit failures.")
		}
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "logging trap was not found."))
	}
	return pass("logging trap is absent. The check states informational is the default, and that level covers audit failure messages.")
}

func trapCoversAuditFailures(level string) bool {
	switch strings.ToLower(level) {
	case "critical", "errors", "error", "warnings", "warning", "notifications", "notification", "informational", "debugging":
		return true
	case "0", "1", "alerts", "alert", "emergencies", "emergency":
		return false
	default:
		if n, err := strconv.Atoi(level); err == nil {
			return n >= 2 && n <= 7
		}
		return false
	}
}

func evalDot1x(ctx checkContext) (string, string, string) {
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
		dot1x := port.Has("authentication port-control auto") && port.Has("dot1x pae authenticator")
		mab := port.Has("mab") || port.HasPrefix("mab ")
		if !dot1x && !mab {
			missing = append(missing, port.InterfaceName())
		}
	}
	if users == 0 {
		return na("The port-role table has no user-facing ports, so there is no LAN-outlet port in scope for 802.1x or MAB.")
	}
	if len(missing) > 0 {
		return fail("User-facing ports " + joinNames(missing) + " have neither 802.1x (authentication port-control auto and dot1x pae authenticator) nor MAB.")
	}
	if !ctx.Config.Has("dot1x system-auth-control") {
		return fail("User-facing ports have 802.1x or MAB, and dot1x system-auth-control is not configured.")
	}
	return pass("Every user-facing port has 802.1x or MAB, and dot1x system-auth-control is configured. RADIUS server state was not observed.")
}

func evalQoSEnabled(ctx checkContext) (string, string, string) {
	if ctx.Config.Has("mls qos") || ctx.Config.HasPrefix("auto qos") || ctx.Config.HasPrefix("policy-map ") || ctx.Config.HasPrefix("class-map ") || commandAnywhere(ctx.Config, "service-policy ") {
		return pass("QoS is enabled by mls qos, auto qos, a class-map, a policy-map, or a service-policy. The example bandwidth values were not compared.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "No QoS policy was found."))
	}
	return fail("QoS is not enabled. The saved configuration has no mls qos, auto qos, class-map, policy-map, or service-policy command.")
}

func evalDirectedBroadcast(ctx checkContext) (string, string, string) {
	if commandAnywhere(ctx.Config, "ip directed-broadcast") && !onlyNegated(ctx.Config, "ip directed-broadcast") {
		return fail("ip directed-broadcast is enabled. The check requires it to be disabled on every interface.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Directed broadcast state was not decided."))
	}
	return pass("No interface enables ip directed-broadcast. The IOS default is disabled, and no enable command is present.")
}

func evalCEF(ctx checkContext) (string, string, string) {
	if ctx.Config.Has("no ip cef") {
		return fail("no ip cef is configured, so Cisco Express Forwarding is disabled.")
	}
	if ctx.Config.Has("ip cef") || ctx.Config.Complete(ctx.Family) {
		return pass("Cisco Express Forwarding is not disabled. On IOS and IOS-XE it is enabled by default when no ip cef is absent.")
	}
	return manual(incomplete(ctx.Family, "CEF state was not decided."))
}

func evalSiteLocal(ctx checkContext) (string, string, string) {
	if commandContains(ctx.Config, "fec0:") {
		return fail("An fec0::/10 IPv6 site-local address is configured.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "IPv6 site-local addresses were not searched in a complete snapshot."))
	}
	return pass("No fec0::/10 site-local address appears in the saved configuration.")
}

func evalMPLSTTL(ctx checkContext) (string, string, string) {
	if !ctx.Config.Has("mpls ip") && !ctx.Config.HasPrefix("mpls ldp") && !ctx.Config.HasPrefix("mpls label") {
		return na("MPLS is not enabled, so disabling TTL propagation does not apply to this snapshot.")
	}
	if ctx.Config.Has("no mpls ip propagate-ttl") {
		return pass("MPLS is enabled and no mpls ip propagate-ttl is configured.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "MPLS TTL propagation was not decided."))
	}
	return fail("MPLS is enabled and no mpls ip propagate-ttl is not configured.")
}

func commandAnywhere(cfg *Config, command string) bool {
	if cfg.Has(command) || cfg.HasPrefix(command) {
		return true
	}
	return cfg.anyBlockHas(command) || cfg.anyBlockPrefix(command)
}

func onlyNegated(cfg *Config, command string) bool {
	return !cfg.Has(command) && !cfg.anyBlockHas(command)
}

func commandContains(cfg *Config, token string) bool {
	token = strings.ToLower(token)
	for line := range cfg.Globals {
		if strings.Contains(strings.ToLower(line), token) {
			return true
		}
	}
	for _, block := range cfg.Blocks {
		for _, line := range block.Lines {
			if strings.Contains(strings.ToLower(line), token) {
				return true
			}
		}
	}
	return false
}

func evalAdminSessionLogging(ctx checkContext) (string, string, string) {
	level, ok := nxFacilityLevel(ctx.Config, "authpriv", "authpri")
	if ok && level >= 6 {
		return pass("logging level authpriv " + itoa(level) + " is configured. Level 6 or 7 records informational session start and end messages. The check text spells the facility authpri; the running configuration uses authpriv.")
	}
	if ok {
		return fail("logging level authpriv is " + itoa(level) + ", which is less verbose than the required informational level 6, so session start and end messages are not logged.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "logging level authpriv was not found."))
	}
	return fail("logging level authpriv 6 is not configured, so administrator session start and end are not logged.")
}

func nxFacilityLevel(cfg *Config, names ...string) (int, bool) {
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for line := range cfg.Globals {
		fields := strings.Fields(line)
		if len(fields) == 4 && fields[0] == "logging" && fields[1] == "level" && allowed[fields[2]] {
			level, err := strconv.Atoi(fields[3])
			if err == nil {
				return level, true
			}
		}
	}
	return 0, false
}

func nxLogfileLevel(cfg *Config) (int, bool) {
	for line := range cfg.Globals {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "logging" && fields[1] == "logfile" {
			level, err := strconv.Atoi(fields[len(fields)-1])
			if err == nil {
				return level, true
			}
		}
	}
	return 0, false
}
