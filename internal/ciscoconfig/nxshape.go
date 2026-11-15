package ciscoconfig

import (
	"net/netip"
	"strconv"
	"strings"
)

// extendNXCommandChecks adds NX-OS forms of checks whose examples use sample
// addresses and names. A different address or name still satisfies the command.
func extendNXCommandChecks() {
	nx := "Cisco_NX-OS_Switch_NDM_STIG"
	extend := func(version, phraseA, phraseB string, id idPair) {
		spec := checks[version]
		if spec.IDs == nil {
			return
		}
		spec.IDs[nx] = id
		if spec.Phrases == nil {
			spec.Phrases = map[string][]string{}
		}
		spec.Phrases[nx] = []string{phraseA, phraseB}
		checks[version] = spec
	}
	extend("CISC-ND-000150", "ssh login-attempts", "this is a finding", idPair{"V-220480", "SV-220480r960840_rule"})
	extend("CISC-ND-000490", "fallback error local", "this is a finding", idPair{"V-220487", "SV-220487r1051115_rule"})
	extend("CISC-ND-000570", "no password strength-check", "this is a finding", idPair{"V-220489", "SV-220489r1026157_rule"})
	extend("CISC-ND-000580", "no password strength-check", "this is a finding", idPair{"V-220490", "SV-220490r1026158_rule"})
	extend("CISC-ND-000590", "no password strength-check", "this is a finding", idPair{"V-220491", "SV-220491r1026159_rule"})
	extend("CISC-ND-000600", "no password strength-check", "this is a finding", idPair{"V-220492", "SV-220492r1026160_rule"})
	extend("CISC-ND-001000", "logging server", "this is a finding", idPair{"V-220497", "SV-220497r991965_rule"})
	extend("CISC-ND-001210", "ssh ciphers aes128-ctr", "this is a finding", idPair{"V-220504", "SV-220504r1026075_rule"})
	extend("CISC-ND-001450", "logging server", "this is a finding", idPair{"V-220516", "SV-220516r1137890_rule"})

	accounting := []struct {
		version, title string
		id             idPair
	}{
		{"CISC-ND-000090", "audit account creation", idPair{"V-220475", "SV-220475r960777_rule"}},
		{"CISC-ND-000100", "audit account modification", idPair{"V-220476", "SV-220476r960780_rule"}},
		{"CISC-ND-000110", "account disabling", idPair{"V-220477", "SV-220477r960783_rule"}},
		{"CISC-ND-000120", "account removal", idPair{"V-220478", "SV-220478r960786_rule"}},
		{"CISC-ND-000210", "falsely denying", idPair{"V-220482", "SV-220482r960864_rule"}},
		{"CISC-ND-000330", "full-text", idPair{"V-220485", "SV-220485r960909_rule"}},
		{"CISC-ND-000880", "audit account enabling", idPair{"V-220494", "SV-220494r961290_rule"}},
		{"CISC-ND-000940", "privileged functions", idPair{"V-220495", "SV-220495r961362_rule"}},
		{"CISC-ND-001240", "privileges are modified", idPair{"V-220506", "SV-220506r961800_rule"}},
		{"CISC-ND-001250", "privileges are deleted", idPair{"V-220507", "SV-220507r961812_rule"}},
		{"CISC-ND-001270", "privileged activities", idPair{"V-220509", "SV-220509r961827_rule"}},
	}
	for _, item := range accounting {
		if checks[item.version].IDs != nil {
			spec := checks[item.version]
			spec.IDs[nx] = item.id
			if spec.Phrases == nil {
				spec.Phrases = map[string][]string{}
			}
			spec.Phrases[nx] = []string{"aaa accounting default group", "this is a finding"}
			checks[item.version] = spec
			continue
		}
		register(checkSpec{
			Version: item.version, Title: item.title, Eval: evalNXAccounting,
			Common: []string{"aaa accounting default group", "this is a finding"},
			IDs:    map[string]idPair{nx: item.id},
		})
	}
	register(checkSpec{
		Version: "CISC-ND-000530", Title: "replay-resistant authentication",
		Common: []string{"ssh macs hmac-sha2-256", "this is a finding"}, Eval: evalNXSSHMacs,
		IDs: map[string]idPair{nx: {"V-220488", "SV-220488r1026069_rule"}},
	})
	register(checkSpec{
		Version: "CISC-ND-001200", Title: "FIPS-validated Keyed-Hash",
		Common: []string{"ssh macs hmac-sha2-256", "this is a finding"}, Eval: evalNXSSHMacs,
		IDs: map[string]idPair{nx: {"V-220503", "SV-220503r1026073_rule"}},
	})
	register(checkSpec{
		Version: "CISC-ND-001310", Title: "off-load log records",
		Common: []string{"logging server", "this is a finding"}, Eval: func(ctx checkContext) (string, string, string) {
			return evalNXLogServers(ctx, 1)
		},
		IDs: map[string]idPair{nx: {"V-220512", "SV-220512r961860_rule"}},
	})
}

func evalNXLoginAttempts(ctx checkContext) (string, string, string) {
	for line := range ctx.Config.Globals {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "ssh" && fields[1] == "login-attempts" {
			n, err := strconv.Atoi(fields[2])
			if err != nil {
				continue
			}
			if n <= 3 {
				return pass("ssh login-attempts " + fields[2] + " limits invalid SSH logons to three or fewer. The example address and names are not required.")
			}
			return fail("ssh login-attempts " + fields[2] + " allows more than three invalid attempts.")
		}
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "ssh login-attempts was not found."))
	}
	return fail("ssh login-attempts 3 is not configured.")
}

func evalNXPasswordStrength(ctx checkContext) (string, string, string) {
	if ctx.Config.Has("no password strength-check") {
		return fail("no password strength-check is configured, so NX-OS password complexity is disabled.")
	}
	if ctx.Config.Has("password strength-check") || ctx.Config.Complete(ctx.Family) {
		return pass("password strength-check is not disabled. NX-OS enables it by default, and the example addresses are not part of this check.")
	}
	return manual(incomplete(ctx.Family, "password strength-check was not decided."))
}

func evalNXLastResort(ctx checkContext) (string, string, string) {
	accounts := 0
	for line := range ctx.Config.Globals {
		if strings.HasPrefix(line, "username ") {
			accounts++
		}
	}
	if ctx.Config.Has("no aaa authentication login default fallback error local") {
		return fail("Local fallback for authentication-server errors is disabled.")
	}
	if accounts != 1 {
		if !ctx.Config.Complete(ctx.Family) && accounts == 0 {
			return manual(incomplete(ctx.Family, "No local username was found."))
		}
		return fail("The configuration has " + itoa(accounts) + " local username commands. This check allows one account of last resort. The example username was not required.")
	}
	return pass("One local username is configured and local fallback remains enabled. The example username and password hash were not required to match.")
}

func evalNXAccounting(ctx checkContext) (string, string, string) {
	if nxAccountingConfigured(ctx.Config) {
		return pass("aaa accounting default group is configured and the group or host commands name at least one RADIUS or TACACS server. Example server addresses and the example group name were not required to match.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "AAA accounting was not found."))
	}
	return fail("aaa accounting default group is not configured with at least one RADIUS or TACACS server.")
}

func nxAccountingConfigured(cfg *Config) bool {
	grouped := false
	for line := range cfg.Globals {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "aaa" && fields[1] == "accounting" && fields[2] == "default" && fields[3] == "group" {
			grouped = true
		}
	}
	if !grouped {
		return false
	}
	if cfg.CountPrefix("radius-server host ") > 0 || cfg.CountPrefix("tacacs-server host ") > 0 || cfg.CountPrefix("radius server ") > 0 || cfg.CountPrefix("tacacs server ") > 0 {
		return true
	}
	for _, block := range cfg.Blocks {
		if strings.HasPrefix(block.Header, "aaa group server radius ") || strings.HasPrefix(block.Header, "aaa group server tacacs+ ") {
			for line := range block.Set {
				if strings.HasPrefix(line, "server ") {
					return true
				}
			}
		}
	}
	return false
}

func evalNXSSHMacs(ctx checkContext) (string, string, string) {
	for line := range ctx.Config.Globals {
		if !strings.HasPrefix(line, "ssh macs ") {
			continue
		}
		if strings.Contains(line, "hmac-sha2-256") && strings.Contains(line, "hmac-sha2-512") {
			return pass("ssh macs includes hmac-sha2-256 and hmac-sha2-512. Example host names are not part of this command.")
		}
		return fail("ssh macs is configured without both hmac-sha2-256 and hmac-sha2-512.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "ssh macs was not found."))
	}
	return fail("ssh macs hmac-sha2-256 hmac-sha2-512 is not configured.")
}

func evalNXSSHCiphers(ctx checkContext) (string, string, string) {
	for line := range ctx.Config.Globals {
		if !strings.HasPrefix(line, "ssh ciphers ") {
			continue
		}
		if strings.Contains(line, "aes128-ctr") && strings.Contains(line, "aes256-ctr") {
			return pass("ssh ciphers includes aes128-ctr and aes256-ctr.")
		}
		return fail("ssh ciphers is configured without both aes128-ctr and aes256-ctr.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "ssh ciphers was not found."))
	}
	return fail("ssh ciphers aes128-ctr aes256-ctr is not configured.")
}

func evalNXAuditLogServers(ctx checkContext) (string, string, string) {
	servers := nxLoggingServers(ctx.Config)
	if len(servers) == 0 {
		if !ctx.Config.Complete(ctx.Family) {
			return manual(incomplete(ctx.Family, "No logging server was found."))
		}
		return fail("No logging server is configured, so audit failure alerts are not sent off the switch.")
	}
	for _, server := range servers {
		if !server.hasLevel || (server.level >= 2 && server.level <= 7) {
			return pass("A logging server is configured at critical or a more verbose level. The example server address was not required to match.")
		}
	}
	return fail("logging server entries are less verbose than critical, so they do not alert on all audit failures.")
}

func evalNXLogServers(ctx checkContext, minimum int) (string, string, string) {
	count := len(nxLoggingServers(ctx.Config))
	if count >= minimum {
		return pass(itoa(count) + " logging server commands are configured. Example server addresses were not required to match.")
	}
	if !ctx.Config.Complete(ctx.Family) {
		return manual(incomplete(ctx.Family, "Fewer logging servers were found than this check requires."))
	}
	return fail("The configuration has " + itoa(count) + " logging server commands and this check requires " + itoa(minimum) + ".")
}

type nxLogServer struct {
	level    int
	hasLevel bool
}

func nxLoggingServers(cfg *Config) []nxLogServer {
	var out []nxLogServer
	for line := range cfg.Globals {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "logging" || fields[1] != "server" {
			continue
		}
		server := nxLogServer{}
		if len(fields) >= 4 {
			if level, err := strconv.Atoi(fields[3]); err == nil {
				server.level = level
				server.hasLevel = true
			}
		}
		out = append(out, server)
	}
	return out
}

// exampleTokenIsPlaceholder reports addresses and sample names from check text.
func exampleTokenIsPlaceholder(token string) bool {
	if token == "" {
		return false
	}
	if _, err := netip.ParseAddr(token); err == nil {
		return true
	}
	if strings.Count(token, ".") >= 3 && strings.ContainsAny(token, "xX") {
		return true
	}
	if token == strings.ToUpper(token) && strings.ContainsAny(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") {
		return true
	}
	return false
}
