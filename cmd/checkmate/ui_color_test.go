package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestStatusBadgesActuallyEmitDistinctColors(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(previous)
	for _, status := range []string{"open", "not_a_finding", "not_applicable", "not_reviewed"} {
		badge := statusBadge(status)
		if !strings.Contains(badge, "\x1b[") {
			t.Errorf("%s is not colored: %q", status, badge)
		}
	}
	if statusBadge("open") == statusBadge("not_a_finding") {
		t.Fatal("status colors indistinguishable")
	}
}
func TestFrameFitsTerminalWithNotice(t *testing.T) {
	m := manyHosts(t, 55)
	m.message = "A comment is required"
	if got := lipgloss.Height(m.View()); got > 24 {
		t.Fatalf("view overflowed height: %d", got)
	}
	for _, line := range strings.Split(m.View(), "\n") {
		if got := lipgloss.Width(line); got > 80 {
			t.Fatalf("view overflowed width: %d", got)
		}
	}
}
