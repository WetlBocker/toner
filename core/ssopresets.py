"""The SSO providers Toner knows how to set up: what the wizard asks for and the claims each one sends."""

PRESETS = {
    "entra": {"label": "Entra", "field": "Tenant ID", "groups_claim": "groups", "id_claim": "oid", "lists_groups": True,
              "note": "In the Entra admin center, register an app for Toner as a public client (mobile and desktop) with the "
                      "redirect URI http://localhost. Add the groups claim and the auth_time optional claim to its ID token, "
                      "and grant GroupMember.Read.All with admin consent so Toner can list groups."},
    "okta": {"label": "Okta", "field": "Issuer URL", "groups_claim": "groups", "id_claim": "sub", "lists_groups": False,
             "note": "In Okta, add an OIDC native app for Toner with the redirect URI http://localhost, and add a groups "
                     "claim to its ID token."},
    "google": {"label": "Google Workspace", "field": "Issuer URL", "groups_claim": None, "id_claim": "sub", "lists_groups": False,
               "note": "In Google Cloud, create an OAuth client of type Desktop app for Toner. Google sends no groups, so "
                       "everyone who signs in gets the role you choose under Roles."},
    "duo": {"label": "Duo SSO", "field": "Issuer URL", "groups_claim": "groups", "id_claim": "sub", "lists_groups": False,
            "note": "In Duo, add a Generic OIDC Relying Party for Toner with the redirect URI http://localhost, and send "
                    "the groups attribute in its ID token."},
    "other": {"label": "Other", "field": "Issuer URL", "groups_claim": "groups", "id_claim": "sub", "lists_groups": False,
              "note": "Register Toner as a native (desktop) app with the redirect URI http://localhost, and add the "
                      "person's groups to its ID token."},
}


def issuer_for(provider, value):
    value = value.strip()
    if provider == "entra":
        return f"https://login.microsoftonline.com/{value}/v2.0"
    return value.rstrip("/")
