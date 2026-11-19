package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestDocsCommandsMatchHelp(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	helps := docketHelps(t)
	checkmateHelp := checkmateHelpText(t, repo)
	scripts := scriptFlagIndex(t, repo)
	var problems []string
	err := filepath.WalkDir(repo, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "vendor", ".git", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(repo, path)
		text := string(body)
		for _, banned := range []string{
			"install-checkmate.sh",
			"scripts/package.sh",
			"cmd/checkmate/vendor",
			"cmd/checkmate/release",
			"map-tailoring-rule-names",
			"./release/checkmate",
		} {
			if strings.Contains(text, banned) {
				problems = append(problems, rel+": still mentions "+banned)
			}
		}
		for _, block := range shellFences(text) {
			for _, statement := range shellStatements(block) {
				problems = append(problems, checkStatement(rel, statement, helps, checkmateHelp, scripts)...)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("%d documentation command problems:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

func docketHelps(t *testing.T) map[string]string {
	t.Helper()
	commands := [][]string{
		{"asset-check"},
		{"reconcile"},
		{"draft-cklb"},
		{"batch-cklb"},
		{"cisco-cklb"},
		{"cisco-batch"},
		{"cisco-xccdf"},
		{"xccdf-cklb"},
		{"tailoring", "check"},
		{"tailoring", "rehash"},
		{"tailoring", "migrate"},
		{"quarter"},
	}
	helps := map[string]string{}
	for _, command := range commands {
		var out, errs bytes.Buffer
		run(append(append([]string{}, command...), "--help"), &out, &errs)
		helps[strings.Join(command, " ")] = out.String() + "\n" + errs.String()
	}
	return helps
}

func checkmateHelpText(t *testing.T, repo string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "checkmate")
	build := exec.Command("go", "build", "-o", bin, "./cmd/checkmate")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build checkmate: %v\n%s", err, out)
	}
	out, _ := exec.Command(bin, "--help").CombinedOutput()
	if !strings.Contains(string(out), "-root") || !strings.Contains(string(out), "-export-tailoring") {
		t.Fatalf("checkmate --help did not list expected flags:\n%s", out)
	}
	return string(out)
}

func scriptFlagIndex(t *testing.T, repo string) map[string]string {
	t.Helper()
	index := map[string]string{}
	roots := []string{filepath.Join(repo, "scripts"), filepath.Join(repo, "cmd", "checkmate", "scripts")}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			body, err := os.ReadFile(filepath.Join(root, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			index[entry.Name()] += string(body) + "\n"
		}
	}
	return index
}

func shellFences(body string) []string {
	var blocks []string
	lines := strings.Split(body, "\n")
	var current strings.Builder
	in := false
	shell := false
	for _, line := range lines {
		if !in && strings.HasPrefix(line, "```") {
			in = true
			lang := strings.TrimSpace(strings.TrimPrefix(line, "```"))
			lang = strings.Split(lang, " ")[0]
			shell = lang == "sh" || lang == "bash" || lang == "shell"
			current.Reset()
			continue
		}
		if in && strings.HasPrefix(line, "```") {
			if shell {
				blocks = append(blocks, current.String())
			}
			in = false
			continue
		}
		if in && shell {
			current.WriteString(line)
			current.WriteByte('\n')
		}
	}
	return blocks
}

func shellStatements(block string) []string {
	var statements []string
	var current strings.Builder
	heredoc := ""
	flush := func() {
		text := strings.TrimSpace(current.String())
		current.Reset()
		if text == "" {
			return
		}
		statements = append(statements, splitStatements(text)...)
	}
	for _, line := range strings.Split(block, "\n") {
		if heredoc != "" {
			if strings.TrimSpace(line) == heredoc {
				heredoc = ""
			}
			continue
		}
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			flush()
			continue
		}
		if delim, ok := heredocDelimiter(trim); ok {
			heredoc = delim
		}
		if strings.HasSuffix(trim, "\\") {
			current.WriteString(strings.TrimSuffix(trim, "\\"))
			current.WriteByte(' ')
			continue
		}
		current.WriteString(trim)
		flush()
	}
	flush()
	return statements
}

func heredocDelimiter(line string) (string, bool) {
	index := strings.Index(line, "<<")
	if index < 0 {
		return "", false
	}
	rest := strings.TrimSpace(line[index+2:])
	rest = strings.TrimPrefix(rest, "-")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	word := rest
	if space := strings.IndexAny(rest, " \t"); space >= 0 {
		word = rest[:space]
	}
	word = strings.Trim(word, "'\"")
	return word, word != ""
}

func splitStatements(line string) []string {
	var parts []string
	var current strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if quote != 0 {
			current.WriteByte(ch)
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			current.WriteByte(ch)
			continue
		}
		if ch == ';' || (ch == '&' && i+1 < len(line) && line[i+1] == '&') || (ch == '|' && i+1 < len(line) && line[i+1] == '|') {
			parts = append(parts, current.String())
			current.Reset()
			if ch != ';' {
				i++
			}
			continue
		}
		current.WriteByte(ch)
	}
	if strings.TrimSpace(current.String()) != "" {
		parts = append(parts, current.String())
	}
	return parts
}

func checkStatement(rel, statement string, helps map[string]string, checkmateHelp string, scripts map[string]string) []string {
	tokens := shellTokens(stripSubstitutions(statement))
	for len(tokens) > 0 && isAssignment(tokens[0]) {
		tokens = tokens[1:]
	}
	if len(tokens) > 0 && tokens[0] == "env" {
		tokens = tokens[1:]
		for len(tokens) > 0 && (isAssignment(tokens[0]) || strings.HasPrefix(tokens[0], "-")) {
			if tokens[0] == "-u" && len(tokens) > 1 {
				tokens = tokens[2:]
				continue
			}
			tokens = tokens[1:]
		}
	}
	if len(tokens) == 0 {
		return nil
	}
	name := filepath.Base(strings.Trim(tokens[0], "'\""))
	args := tokens[1:]
	switch name {
	case "docket":
		return checkDocket(rel, statement, args, helps)
	case "checkmate":
		return checkFlags(rel, statement, "checkmate", args, checkmateHelp)
	default:
		body, ok := scripts[name]
		if !ok {
			return nil
		}
		return checkScriptFlags(rel, statement, name, args, body)
	}
}

func checkDocket(rel, statement string, args []string, helps map[string]string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return []string{rel + ": docket needs a subcommand: " + statement}
	}
	key := args[0]
	rest := args[1:]
	if key == "tailoring" {
		if len(rest) == 0 || (rest[0] != "check" && rest[0] != "rehash" && rest[0] != "migrate") {
			return []string{rel + ": docket tailoring needs check, rehash, or migrate: " + statement}
		}
		key = "tailoring " + rest[0]
		rest = rest[1:]
	}
	help, ok := helps[key]
	if !ok {
		return []string{rel + ": unknown docket command " + key + ": " + statement}
	}
	return checkFlags(rel, statement, key, rest, help)
}

func checkFlags(rel, statement, command string, args []string, help string) []string {
	var problems []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		name := arg
		if eq := strings.Index(arg, "="); eq >= 0 {
			name = arg[:eq]
		}
		if name == "--help" || name == "-h" || name == "--" {
			continue
		}
		bare := strings.TrimLeft(name, "-")
		if bare == "" || (!strings.Contains(help, "-"+bare) && !strings.Contains(help, "--"+bare)) {
			problems = append(problems, rel+": "+command+" has no "+name+": "+statement)
		}
	}
	return problems
}

func checkScriptFlags(rel, statement, name string, args []string, body string) []string {
	var problems []string
	for _, arg := range args {
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		flagName := arg
		if eq := strings.Index(arg, "="); eq >= 0 {
			flagName = arg[:eq]
		}
		if flagName == "--help" || flagName == "--" {
			continue
		}
		if !strings.Contains(body, flagName) {
			problems = append(problems, rel+": "+name+" has no "+flagName+": "+statement)
		}
	}
	return problems
}

func stripSubstitutions(line string) string {
	var out strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] == '`' {
			end := strings.Index(line[i+1:], "`")
			if end < 0 {
				break
			}
			out.WriteString(" VALUE ")
			i += end + 1
			continue
		}
		if line[i] == '$' && i+1 < len(line) && line[i+1] == '(' {
			depth := 1
			j := i + 2
			for j < len(line) && depth > 0 {
				if line[j] == '(' {
					depth++
				} else if line[j] == ')' {
					depth--
				}
				j++
			}
			out.WriteString(" VALUE ")
			i = j - 1
			continue
		}
		out.WriteByte(line[i])
	}
	return out.String()
}

func shellTokens(line string) []string {
	var tokens []string
	var current strings.Builder
	quote := byte(0)
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
				continue
			}
			current.WriteByte(ch)
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case ' ', '\t':
			flush()
		case '#':
			flush()
			return tokens
		default:
			current.WriteByte(ch)
		}
	}
	flush()
	return tokens
}

func isAssignment(token string) bool {
	return regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`).MatchString(token)
}
