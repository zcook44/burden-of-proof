package ciscoconfig

import (
	"strconv"
	"strings"
)

func registerNDM() {
	xe := "Cisco_IOS_XE_Switch_NDM_STIG"
	ios := "Cisco_IOS_Switch_NDM_STIG"
	nx := "Cisco_NX-OS_Switch_NDM_STIG"
	archive := func(version, title, phrase string, xeID, iosID idPair) {
		ids := map[string]idPair{}
		if xeID.Group != "" {
			ids[xe] = xeID
		}
		if iosID.Group != "" {
			ids[ios] = iosID
		}
		register(checkSpec{
			Version: version, Title: title, Common: []string{"logging enable", phrase}, Eval: evalArchiveLogging, IDs: ids,
		})
	}
	archive("CISC-ND-000090", "audit account creation", "account creation",
		idPair{"V-220519", "SV-220519r1186338_rule"}, idPair{})
	archive("CISC-ND-000100", "audit account modification", "account modification",
		idPair{"V-220520", "SV-220520r1186340_rule"}, idPair{})
	archive("CISC-ND-000110", "audit account disabling", "account disabling",
		idPair{"V-220521", "SV-220521r1186342_rule"}, idPair{})
	archive("CISC-ND-000120", "audit account removal", "account removal",
		idPair{"V-220522", "SV-220522r1186344_rule"}, idPair{})
	archive("CISC-ND-000210", "audit all administrator activity", "administrator activity",
		idPair{"V-220526", "SV-220526r1186346_rule"}, idPair{"V-220578", "SV-220578r1205849_rule"})
	archive("CISC-ND-000330", "full-text", "logging enable",
		idPair{"V-220530", "SV-220530r1186348_rule"}, idPair{})
	archive("CISC-ND-000880", "audit account enabling", "account enabling",
		idPair{"V-220545", "SV-220545r1186350_rule"}, idPair{})
	archive("CISC-ND-001250", "administrator privileges are deleted", "administrator privileges",
		idPair{"V-220559", "SV-220559r1186352_rule"}, idPair{})
	archive("CISC-ND-001270", "privileged activities", "privileged activities",
		idPair{"V-220561", "SV-220561r1186354_rule"}, idPair{})

	both := func(version, title string, phrases []string, xeID, iosID idPair, eval func(checkContext) (string, string, string)) {
		register(checkSpec{Version: version, Title: title, Common: phrases, Eval: eval, IDs: map[string]idPair{xe: xeID, ios: iosID}})
	}
	both("CISC-ND-000280", "date and time", []string{"service timestamps log datetime", "this is a finding"},
		idPair{"V-220528", "SV-220528r960894_rule"}, idPair{"V-220580", "SV-220580r960894_rule"}, evalLogTimestamps)
	both("CISC-ND-000620", "cryptographic representations", []string{"service password-encryption", "this is a finding"},
		idPair{"V-220543", "SV-220543r991922_rule"}, idPair{"V-220595", "SV-220595r1015286_rule"}, evalPasswordEncryption)
	both("CISC-ND-000980", "audit record storage", []string{"logging buffered", "this is a finding"},
		idPair{"V-220547", "SV-220547r961392_rule"}, idPair{"V-220599", "SV-220599r961392_rule"}, evalLoggingBuffered)
	both("CISC-ND-001210", "confidentiality of remote", []string{"ip ssh version 2", "this is a finding"},
		idPair{"V-220556", "SV-220556r961557_rule"}, idPair{"V-220608", "SV-220608r961557_rule"}, evalSSH)
	register(checkSpec{
		Version: "CISC-ND-001260", Title: "logon attempts",
		Common: []string{"login on-failure log", "login on-success log"},
		Phrases: map[string][]string{
			"Cisco_NX-OS_Switch_NDM_STIG": {"logging level authpri 6", "logging logfile", "this is a finding"},
		},
		Eval: evalLogonAudit,
		IDs: map[string]idPair{
			"Cisco_IOS_XE_Switch_NDM_STIG": {"V-220560", "SV-220560r961824_rule"},
			"Cisco_IOS_Switch_NDM_STIG":    {"V-220612", "SV-220612r961824_rule"},
			"Cisco_NX-OS_Switch_NDM_STIG":  {"V-220508", "SV-220508r961824_rule"},
		},
	})
	both("CISC-ND-001450", "at least two", []string{"central log servers", "this is a finding"},
		idPair{"V-220568", "SV-220568r1137890_rule"}, idPair{"V-220620", "SV-220620r1137890_rule"}, evalLogHosts)

	register(checkSpec{
		Version: "CISC-ND-000720", Title: "terminate all network connections",
		Common: []string{"exec-timeout", "five minutes"}, Eval: evalExecTimeout,
		IDs: map[string]idPair{
			xe:  {"V-220544", "SV-220544r961068_rule"},
			ios: {"V-220596", "SV-220596r961068_rule"},
			nx:  {"V-220493", "SV-220493r961068_rule"},
		},
	})
	register(checkSpec{
		Version: "CISC-ND-001030", Title: "synchronize its clock",
		Common: []string{"ntp server", "this is a finding"}, Eval: evalNTPServers,
		IDs: map[string]idPair{
			xe:  {"V-220549", "SV-220549r991924_rule"},
			ios: {"V-220601", "SV-220601r1269407_rule"},
			nx:  {"V-220498", "SV-220498r1026071_rule"},
		},
	})
	register(checkSpec{
		Version: "CISC-ND-001150", Title: "authenticate Network Time Protocol",
		Common: []string{"ntp authentication-key", "this is a finding"}, Eval: evalNTPAuth,
		IDs: map[string]idPair{
			xe:  {"V-220554", "SV-220554r1107160_rule"},
			ios: {"V-220606", "SV-220606r1156814_rule"},
			nx:  {"V-220502", "SV-220502r1156823_rule"},
		},
	})
	register(checkSpec{
		Version: "CISC-ND-001370", Title: "at least two authentication servers",
		Common: []string{"authentication servers", "this is a finding"}, Eval: evalAuthServers,
		IDs: map[string]idPair{
			xe:  {"V-220565", "SV-220565r1195273_rule"},
			ios: {"V-220617", "SV-220617r1205840_rule"},
			nx:  {"V-220513", "SV-220513r1137887_rule"},
		},
	})
}

func evalArchiveLogging(ctx checkContext) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXAccounting(ctx)
	}
	for _, block := range ctx.Config.Blocks {
		if block.Header == "archive" && block.Has("log config") && block.Has("logging enable") {
			return pass("archive log config logging enable is present. The command records configuration changes; it does not by itself prove each audited event type is complete.")
		}
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Configuration-change logging was not found."))
	}
	return fail("archive log config logging enable is not present, so configuration changes are not logged by the method this check shows.")
}

func evalLogTimestamps(ctx checkContext) (string, string, string) {
	if ctx.Config.HasPrefix("service timestamps log datetime") {
		return pass("service timestamps log datetime is configured, so log records include a timestamp.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Log timestamps were not found."))
	}
	return fail("service timestamps log datetime is not configured.")
}

func evalPasswordEncryption(ctx checkContext) (string, string, string) {
	if ctx.Config.Has("service password-encryption") {
		return pass("service password-encryption is configured. Secret values were not copied, and this does not prove every local secret uses a strong hash.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Password encryption was not found."))
	}
	return fail("service password-encryption is not configured.")
}

func evalExecTimeout(ctx checkContext) (string, string, string) {
	var lines []*Block
	for _, block := range ctx.Config.Blocks {
		if len(block.Header) >= 5 && block.Header[:5] == "line " {
			lines = append(lines, block)
		}
	}
	if len(lines) == 0 {
		return manual("No line con or line vty blocks were found, so the management idle timeout was not decided.")
	}
	var slow []string
	for _, line := range lines {
		seconds, ok := execTimeoutSeconds(line)
		if !ok || seconds > 5*60 {
			slow = append(slow, line.Header)
		}
	}
	if len(slow) > 0 {
		return fail("Management lines exceed five minutes of idle time or have no exec-timeout: " + joinNames(slow) + ".")
	}
	return pass("Every line con and line vty block sets exec-timeout to five minutes or less.")
}

func execTimeoutSeconds(line *Block) (int, bool) {
	raw := line.FirstPrefix("exec-timeout ")
	if raw == "" {
		return 0, false
	}
	fields := splitFields(raw)
	if len(fields) < 2 || fields[0] != "exec-timeout" {
		return 0, false
	}
	minutes, err := strconv.Atoi(fields[1])
	if err != nil || minutes < 0 {
		return 0, false
	}
	seconds := 0
	if len(fields) >= 3 {
		seconds, err = strconv.Atoi(fields[2])
		if err != nil || seconds < 0 || seconds > 59 {
			return 0, false
		}
	}
	return minutes*60 + seconds, true
}

func evalLoggingBuffered(ctx checkContext) (string, string, string) {
	if ctx.Config.HasPrefix("logging buffered ") {
		return pass("logging buffered is configured. The organization-defined size was not compared.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "A logging buffer was not found."))
	}
	return fail("logging buffered is not configured.")
}

func evalNTPServers(ctx checkContext) (string, string, string) {
	if ctx.Config.CountPrefix("ntp server ") >= 2 {
		return pass("At least two ntp server commands are present. Reachability of those servers was not observed.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Fewer than two NTP servers were found."))
	}
	return fail("Fewer than two ntp server commands are present.")
}

func evalNTPAuth(ctx checkContext) (string, string, string) {
	if ctx.Config.HasPrefix("ntp authentication-key ") && ctx.Config.Has("ntp authenticate") && ctx.Config.HasPrefix("ntp trusted-key ") {
		return pass("ntp authenticate, a trusted key, and an authentication-key command are present. The key material was not copied and was not judged.")
	}
	if !ctx.Config.Complete(ctx.Family) && !ctx.Config.Has("ntp authenticate") {
		return manual(incomplete(ctx.Family, "NTP authentication commands were not found."))
	}
	return fail("Authenticated NTP is incomplete. This check expects ntp authentication-key, ntp authenticate, and ntp trusted-key. Key material was not copied.")
}

func evalSSH(ctx checkContext) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXSSHCiphers(ctx)
	}
	if !ctx.Config.Has("ip ssh version 2") {
		if !ctx.Config.Complete(ctx.Family) {
			return manual(incomplete(ctx.Family, "SSH version 2 was not found."))
		}
		return fail("ip ssh version 2 is not configured.")
	}
	if !ctx.Config.HasPrefix("ip ssh server algorithm encryption ") {
		return fail("ip ssh version 2 is set, and the FIPS cipher list ip ssh server algorithm encryption is not present.")
	}
	return pass("SSH version 2 and an encryption algorithm list are configured. The algorithm names were not judged against the current FIPS set.")
}

func evalLogonAudit(ctx checkContext) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXAuthprivLogon(ctx)
	}
	if ctx.Config.Has("login on-failure log") && ctx.Config.Has("login on-success log") {
		return pass("login on-failure log and login on-success log are both configured.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Logon auditing commands were not found."))
	}
	return fail("Both login on-failure log and login on-success log are required, and at least one is missing.")
}

// evalNXAuthprivLogon closes the NX-OS logon check when the commands in the
// official example are present. The check text spells the facility "authpri";
// a running configuration records the real facility name "authpriv".
func evalNXAuthprivLogon(ctx checkContext) (string, string, string) {
	level, ok := nxFacilityLevel(ctx.Config, "authpriv", "authpri")
	logfile, logOK := nxLogfileLevel(ctx.Config)
	if ok && level >= 6 && logOK && logfile >= 6 {
		return pass("logging level authpriv " + itoa(level) + " and a logging logfile at level " + itoa(logfile) + " or more verbose are configured. Level 6 is informational, which is the example this check requires.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "NX-OS authpriv logging was not found."))
	}
	return fail("NX-OS logon auditing requires logging level authpriv 6 or 7 and logging logfile at level 6 or 7. The saved configuration does not have both.")
}

func evalLogHosts(ctx checkContext) (string, string, string) {
	if ctx.BenchmarkID == "Cisco_NX-OS_Switch_NDM_STIG" {
		return evalNXLogServers(ctx, 2)
	}
	if ctx.Config.CountPrefix("logging host ") >= 2 {
		return pass("At least two logging host commands are present. Delivery to those servers was not observed.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Fewer than two logging hosts were found."))
	}
	return fail("Fewer than two logging host commands are present.")
}

func evalAuthServers(ctx checkContext) (string, string, string) {
	servers := ctx.Config.CountPrefix("tacacs server ") + ctx.Config.CountPrefix("tacacs-server host ") + ctx.Config.CountPrefix("radius server ") + ctx.Config.CountPrefix("radius-server host ")
	login := ctx.Config.HasPrefix("aaa authentication login ")
	if servers >= 2 && login {
		return pass("At least two TACACS or RADIUS server commands are present and aaa authentication login references a method list. Server reachability and shared keys were not judged.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Two authentication servers were not found."))
	}
	return fail("The configuration does not show two TACACS or RADIUS servers used by aaa authentication login.")
}

func splitFields(line string) []string {
	return strings.Fields(line)
}
