package firewall

# CyberCity provenance-aware tool firewall.
#
# Input shape:
#   {
#     "session_user":      string,
#     "target_owner":      string,
#     "tool":              string,
#     "doc_read":          bool,
#     "resident_confirmed": bool,
#     "args": { <name>: {"value": ..., "origin": "user_typed" | "from_document" | "from_system"} },
#     "recent_calls":      [{"tool": string}, ...],
#     "personal_values":   [string, ...]
#   }
#
# Output at data.firewall.result:
#   { "decision": "allow" | "confirm" | "deny", "reasons": [string, ...] }

import future.keywords.contains
import future.keywords.every
import future.keywords.if
import future.keywords.in

default result := {"decision": "allow", "reasons": []}

# ---- Deny rules ----------------------------------------------------------

deny contains msg if {
	input.target_owner != input.session_user
	msg := "This record belongs to another resident."
}

deny contains msg if {
	input.tool == "update_contact"
	some field
	field in {"new_email", "new_phone"}
	arg := input.args[field]
	arg.origin != "user_typed"
	pretty := field_label[field]
	msg := sprintf(
		"Detected an instruction to change your %s to %v. That value came from the uploaded document, not from you, so the change was blocked. If you really want it, type it yourself in the chat below, or open Account settings and change it there.",
		[pretty, arg.value],
	)
}

field_label := {
	"new_email": "email",
	"new_phone": "phone number",
}

deny contains msg if {
	input.tool == "send_password_reset"
	input.doc_read
	msg := "A password reset can't be triggered by document content. Start one yourself from the login page."
}

deny contains msg if {
	input.tool == "send_password_reset"
	some call in input.recent_calls
	call.tool == "update_contact"
	msg := "A password reset can't follow a contact change in the same session. Verify through the old contact first."
}

deny contains msg if {
	input.tool == "render_link"
	url := input.args.url.value
	some personal in input.personal_values
	personal != ""
	contains(url, personal)
	msg := sprintf("This link would send your personal data (%s) outside the portal.", [personal])
}

deny contains msg if {
	input.tool == "admin_export_all_users"
	msg := "No resident request needs an administrative export. This is a honey tool and its use freezes the session."
}

deny contains msg if {
	input.tool == "cancel_appointment"
	count([c | c := input.recent_calls[_]; c.tool == "cancel_appointment"]) >= 1
	msg := "Only one cancellation per session. Contact city hall to cancel more."
}

# ---- Confirm rules -------------------------------------------------------

# Reschedule / cancel where the document drove the decision or a field is not
# typed by the resident. Bypassed once the resident has clicked confirm.
confirm contains msg if {
	input.tool == "reschedule_appointment"
	not input.resident_confirmed
	trigger_confirmation
	msg := reschedule_reason
}

confirm contains msg if {
	input.tool == "cancel_appointment"
	not input.resident_confirmed
	trigger_confirmation
	count([c | c := input.recent_calls[_]; c.tool == "cancel_appointment"]) == 0
	msg := cancel_reason
}

trigger_confirmation if input.doc_read

trigger_confirmation if {
	some k
	arg := input.args[k]
	arg.origin != "user_typed"
}

non_typed_fields := sorted if {
	pairs := [pair |
		some k
		arg := input.args[k]
		arg.origin != "user_typed"
		pair := sprintf("%s=%v (from %s)", [k, arg.value, arg.origin])
	]
	sorted := sort(pairs)
}

reschedule_reason := msg if {
	count(non_typed_fields) > 0
	msg := sprintf(
		"These fields were not typed by you: %s. Confirm before we move the appointment.",
		[concat(", ", non_typed_fields)],
	)
}

reschedule_reason := "The reschedule was triggered by an uploaded document. Confirm before we change your appointment." if {
	count(non_typed_fields) == 0
	input.doc_read
}

cancel_reason := msg if {
	count(non_typed_fields) > 0
	msg := sprintf(
		"These fields were not typed by you: %s. Confirm before we cancel the appointment.",
		[concat(", ", non_typed_fields)],
	)
}

cancel_reason := "The cancellation was triggered by an uploaded document. Confirm before we cancel your appointment." if {
	count(non_typed_fields) == 0
	input.doc_read
}

# ---- Final decision ------------------------------------------------------

deny_reasons := [r | r := deny[_]]

confirm_reasons := [r | r := confirm[_]]

result := {"decision": "deny", "reasons": deny_reasons} if {
	count(deny_reasons) > 0
}

result := {"decision": "confirm", "reasons": confirm_reasons} if {
	count(deny_reasons) == 0
	count(confirm_reasons) > 0
}

result := {"decision": "allow", "reasons": []} if {
	count(deny_reasons) == 0
	count(confirm_reasons) == 0
}
