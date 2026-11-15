package ciscoconfig

import "strings"

// FallbackReason explains a control the pinned checks did not score.
// The comment is what an administrator sees and can replace in the device tailoring file.
func FallbackReason(version, title, check string) (string, string) {
	why := fallbackWhy(version, title, check)
	return why + " Manual review of the saved running config is required.", "NOT REVIEWED — " + why
}

func fallbackWhy(version, title, check string) string {
	text := strings.ToLower(title + " " + check)
	switch {
	case strings.Contains(text, "show version") || strings.Contains(text, "supported by cisco"):
		return "The running configuration cannot prove the installed release is still supported. Compare show version with Cisco's current supported-release list, then set the status in this device's tailoring file."
	case strings.Contains(text, "banner"):
		return "The banner text is not used as command evidence. Compare the banner body with the required notice, then set the status and replace this comment in the device tailoring file."
	case strings.Contains(text, "organization-defined") || strings.Contains(text, "organizational"):
		return "The check compares the device with an organization-defined value that is not in the running configuration. Record that value and set the status in this device's tailoring file."
	case strings.Contains(text, "approved") || strings.Contains(text, "authorized"):
		return "The running configuration shows what is configured, not which networks, peers, or filters are approved. Record the approval and set the status in this device's tailoring file."
	case strings.Contains(version, "CISC-RT") && (strings.Contains(text, "external") || strings.Contains(text, "perimeter") || strings.Contains(text, "ce-facing") || strings.Contains(text, "pe switch") || strings.Contains(text, "mpls")):
		return "This control depends on a role the running configuration does not label, such as perimeter, PE, or external. Add that fact and set the status in this device's tailoring file."
	case strings.Contains(text, "show "):
		return "The official check calls for show-command output that was not supplied with the running configuration. Attach that output and set the status in this device's tailoring file."
	default:
		return "No pinned check proves this control from the running configuration alone. Inspect the official check text and set the status in this device's tailoring file."
	}
}
