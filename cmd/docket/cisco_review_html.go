package main

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
)

type reviewLink struct {
	Host      string
	Benchmark string
	Href      string
	Counts    map[string]int
	Complete  bool
}

type reviewRule struct {
	Group    string
	Rule     string
	Version  string
	Severity string
	Title    string
	Status   string
	Comments string
	Details  string
}

func reviewHTML(host, benchmark string, complete bool, tailoring string, doc map[string]any) ([]byte, error) {
	stig := doc["stigs"].([]any)[0].(map[string]any)
	var rules []reviewRule
	counts := map[string]int{}
	for _, item := range stig["rules"].([]any) {
		row := item.(map[string]any)
		status := row["status"].(string)
		counts[status]++
		rules = append(rules, reviewRule{
			Group: row["group_id"].(string), Rule: row["rule_id"].(string), Version: row["rule_version"].(string),
			Severity: row["severity"].(string), Title: row["rule_title"].(string), Status: status,
			Comments: row["comments"].(string), Details: row["finding_details"].(string),
		})
	}
	return renderReview("checklist", map[string]any{
		"Host": host, "Benchmark": benchmark, "Title": doc["title"], "Complete": complete,
		"Tailoring": tailoring, "Counts": counts, "Total": len(rules), "Rules": rules,
		"Device": deviceCardFrom(doc),
	})
}

type deviceCard struct {
	FQDN, IP, MAC, Role, Type, Area string
}

func deviceCardFrom(doc map[string]any) deviceCard {
	td, _ := doc["target_data"].(map[string]any)
	text := func(key string) string {
		value, _ := td[key].(string)
		return value
	}
	return deviceCard{FQDN: text("fqdn"), IP: text("ip_address"), MAC: text("mac_address"), Role: text("role"), Type: text("target_type"), Area: text("technology_area")}
}

func reviewIndex(links []reviewLink) ([]byte, error) {
	sort.Slice(links, func(i, j int) bool {
		if links[i].Host == links[j].Host {
			return links[i].Benchmark < links[j].Benchmark
		}
		return links[i].Host < links[j].Host
	})
	return renderReview("index", map[string]any{"Links": links, "Total": len(links)})
}

func renderReview(name string, data map[string]any) ([]byte, error) {
	tmpl, err := template.New("review").Parse(reviewTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, fmt.Errorf("review html: %w", err)
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

const reviewTemplate = `{{define "index"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cisco STIG review package</title>
<style>
body { margin: 0; font: 16px/1.45 "Iowan Old Style", Palatino, Georgia, serif; background: #f4f1ea; color: #1c1915; }
main { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 1.8rem; margin-bottom: 0.2rem; }
p { max-width: 68ch; }
table { width: 100%; border-collapse: collapse; background: white; }
th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #ddd6c8; vertical-align: top; }
a { color: #1f4b3a; }
.note { background: #fff7e8; border: 1px solid #e0d2b4; padding: 12px 14px; }
</style>
</head>
<body>
<main>
<h1>Cisco review package</h1>
<p class="note">These {{.Total}} checklists are review candidates built from saved configuration and a port-role table. They are not an approved assessment. The CKLB beside each page is the file STIG Viewer opens. Judge every rule on that device, including every Not a Finding.</p>
<table>
<thead><tr><th>Device</th><th>Benchmark</th><th>Open</th><th>Not reviewed</th><th>Not applicable</th><th>Not a finding</th></tr></thead>
<tbody>
{{range .Links}}<tr>
<td>{{.Host}}{{if not .Complete}} <em>(incomplete snapshot)</em>{{end}}</td>
<td><a href="{{.Href}}">{{.Benchmark}}</a></td>
<td>{{index .Counts "open"}}</td>
<td>{{index .Counts "not_reviewed"}}</td>
<td>{{index .Counts "not_applicable"}}</td>
<td>{{index .Counts "not_a_finding"}}</td>
</tr>{{end}}
</tbody>
</table>
</main>
</body>
</html>
{{end}}
{{define "checklist"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Host}} {{.Benchmark}}</title>
<style>
body { margin: 0; font: 16px/1.45 "Iowan Old Style", Palatino, Georgia, serif; background: #f4f1ea; color: #1c1915; }
header { position: sticky; top: 0; background: #1c1915; color: #f4f1ea; padding: 14px 20px; z-index: 2; }
header h1 { font-size: 1.15rem; margin: 0 0 8px; }
header button, header input { font: inherit; margin-right: 8px; }
main { max-width: 1080px; margin: 0 auto; padding: 20px; }
article { background: white; border: 1px solid #ddd6c8; margin: 0 0 12px; padding: 12px 14px; }
article h2 { font-size: 1.05rem; margin: 0 0 6px; }
.meta { color: #514a40; font-size: 0.92rem; }
.status { display: inline-block; padding: 2px 8px; font-weight: 700; }
.open { background: #f8d0cb; }
.not_a_finding { background: #d7eadb; }
.not_applicable { background: #e4e7ee; }
.not_reviewed { background: #f8e7c2; }
pre { white-space: pre-wrap; font: 0.92rem/1.4 ui-monospace, monospace; background: #f7f5f0; padding: 10px; }
.hidden { display: none; }
</style>
</head>
<body>
<header>
<h1>{{.Host}} — {{.Benchmark}}</h1>
{{if .Device.FQDN}}<p style="margin:0 0 8px">{{.Device.FQDN}} · {{.Device.IP}} · {{.Device.MAC}} · {{.Device.Role}} · {{.Device.Type}} · {{.Device.Area}}</p>{{end}}
<p style="margin:0 0 8px">{{.Total}} controls. Open {{index .Counts "open"}}, not reviewed {{index .Counts "not_reviewed"}}, not applicable {{index .Counts "not_applicable"}}, not a finding {{index .Counts "not_a_finding"}}.{{if not .Complete}} Snapshot is incomplete; missing commands were not scored as findings.{{end}}{{if .Tailoring}} Not Reviewed reasons are in {{.Tailoring}}; change a row there and copy it to the device directory to apply it.{{end}}</p>
<div>
<button type="button" data-filter="all">All</button>
<button type="button" data-filter="open">Open</button>
<button type="button" data-filter="not_reviewed">Not reviewed</button>
<button type="button" data-filter="not_applicable">Not applicable</button>
<button type="button" data-filter="not_a_finding">Not a finding</button>
<input id="q" type="search" placeholder="Filter by V-ID or title" aria-label="Filter rules">
</div>
</header>
<main id="rules">
{{range .Rules}}
<article data-status="{{.Status}}" data-text="{{.Group}} {{.Title}}">
<p class="meta"><span class="status {{.Status}}">{{.Status}}</span> {{.Severity}} · {{.Group}} · {{.Rule}} · {{.Version}}</p>
<h2>{{.Title}}</h2>
<p>{{.Comments}}</p>
<details><summary>Finding details</summary><pre>{{.Details}}</pre></details>
</article>
{{end}}
</main>
<script>
const buttons = document.querySelectorAll("header button");
const q = document.getElementById("q");
let status = "all";
function apply() {
  const query = q.value.toLowerCase();
  for (const row of document.querySelectorAll("#rules article")) {
    const statusOK = status === "all" || row.dataset.status === status;
    const textOK = row.dataset.text.toLowerCase().includes(query);
    row.classList.toggle("hidden", !(statusOK && textOK));
  }
}
for (const button of buttons) {
  button.addEventListener("click", () => { status = button.dataset.filter; apply(); });
}
q.addEventListener("input", apply);
</script>
</body>
</html>
{{end}}`
