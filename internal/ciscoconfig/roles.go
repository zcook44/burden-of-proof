package ciscoconfig

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// PortRole is an operator-confirmed classification for one switch interface.
// The running configuration does not say which ports face users, uplinks, or fiber.
type PortRole struct {
	Interface  string
	Role       string
	UserFacing bool
	Fiber      bool
}

// RoleTable is omitted when Supplied is false. An empty supplied table is
// different: every switch port was considered and none were listed.
type RoleTable struct {
	Supplied bool
	ByName   map[string]PortRole
}

func (t RoleTable) Fingerprint() string {
	if !t.Supplied {
		return "roles:none"
	}
	names := make([]string, 0, len(t.ByName))
	for name := range t.ByName {
		names = append(names, name)
	}
	sortStrings(names)
	var b strings.Builder
	for _, name := range names {
		role := t.ByName[name]
		fmt.Fprintf(&b, "%s|%s|%t|%t\n", name, role.Role, role.UserFacing, role.Fiber)
	}
	return b.String()
}

// ParsePortRoles reads a headered CSV: interface,role,user_facing,fiber.
// role is user, uplink, unused, access-switch, or routed.
func ParsePortRoles(data []byte) (RoleTable, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	reader.FieldsPerRecord = 4
	reader.TrimLeadingSpace = true
	header, err := reader.Read()
	if err != nil {
		return RoleTable{}, fmt.Errorf("port-role table: %w", err)
	}
	want := []string{"interface", "role", "user_facing", "fiber"}
	for i, column := range want {
		if strings.ToLower(strings.TrimSpace(header[i])) != column {
			return RoleTable{}, fmt.Errorf("port-role table header must be interface,role,user_facing,fiber")
		}
	}
	table := RoleTable{Supplied: true, ByName: map[string]PortRole{}}
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return RoleTable{}, fmt.Errorf("port-role table: %w", err)
		}
		name := row[0]
		role := row[1]
		switch role {
		case "user", "uplink", "unused", "access-switch", "routed":
		default:
			return RoleTable{}, fmt.Errorf("port-role table: invalid role %q for %s", role, name)
		}
		user, ok := yesNo(row[2])
		if !ok {
			return RoleTable{}, fmt.Errorf("port-role table: user_facing must be yes or no for %s", name)
		}
		fiber, ok := yesNo(row[3])
		if !ok {
			return RoleTable{}, fmt.Errorf("port-role table: fiber must be yes or no for %s", name)
		}
		if (role == "user") != user {
			return RoleTable{}, fmt.Errorf("port-role table: role user and user_facing disagree for %s", name)
		}
		if name == "" || strings.Contains(name, " ") {
			return RoleTable{}, fmt.Errorf("port-role table: invalid interface name %q", name)
		}
		if _, exists := table.ByName[name]; exists {
			return RoleTable{}, fmt.Errorf("port-role table: duplicate interface %s", name)
		}
		table.ByName[name] = PortRole{Interface: name, Role: role, UserFacing: user, Fiber: fiber}
	}
	if len(table.ByName) == 0 {
		return RoleTable{}, fmt.Errorf("port-role table has no interfaces")
	}
	return table, nil
}

func yesNo(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true":
		return true, true
	case "no", "false":
		return false, true
	default:
		return false, false
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// UnknownInterfaces returns CSV rows that do not exist in the snapshot.
func UnknownInterfaces(cfg *Config, roles RoleTable) []string {
	var missing []string
	for name := range roles.ByName {
		if cfg.Interface(name) == nil {
			missing = append(missing, name)
		}
	}
	sortStrings(missing)
	return missing
}

// roleGate reports whether every switch port in the snapshot has a role.
// Checks that depend on topology stay Not Reviewed until this is true.
func roleGate(cfg *Config, roles RoleTable) (bool, string) {
	if !roles.Supplied {
		return false, "No port-role table was supplied, so interface and topology checks stay unreviewed."
	}
	var missing []string
	for _, port := range cfg.Switchports() {
		if _, ok := roles.ByName[port.InterfaceName()]; !ok {
			missing = append(missing, port.InterfaceName())
		}
	}
	if len(missing) > 0 {
		return false, "Port-role table does not name every switch port (" + joinNames(missing) + ")."
	}
	return true, ""
}

func joinNames(names []string) string {
	if len(names) > 6 {
		return strings.Join(names[:6], ", ") + fmt.Sprintf(", and %d more", len(names)-6)
	}
	return strings.Join(names, ", ")
}
