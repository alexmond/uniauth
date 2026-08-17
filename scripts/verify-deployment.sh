#!/usr/bin/env bash
#
# Usage:
#   WEBAPP=http://... API=http://... AUTH=http://... CONSOLE=http://... \
#     scripts/verify-deployment.sh
#
# Hostnames come from the environment: they are deployment facts, and this repo carries no
# domain of its own.
# Post-deploy verification.
#
# Exercises the DEPLOYED configuration through the same paths a user takes, rather than
# asserting that a pod is Ready. Ready only proves the management port answers.

WEBAPP=${WEBAPP:?set WEBAPP, e.g. http://uniauth.example.com}
API=${API:?set API}
AUTH=${AUTH:?set AUTH}
CONSOLE=${CONSOLE:?set CONSOLE}

PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; printf '       %s\n' "$2"; FAIL=$((FAIL+1)); }
check(){ # check <label> <actual> <expected-substring>
  case "$2" in *"$3"*) ok "$1";; *) bad "$1" "expected '$3', got: $2";; esac
}
section(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

# Sign in with the shared username/password form; echoes the cookie jar path.
form_login() { # <base> <user> <pass> <jar>
  local base=$1 user=$2 pass=$3 jar=$4
  local t
  t=$(curl -s -c "$jar" "$base/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
  curl -s -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=$user" --data-urlencode "password=$pass" \
    --data-urlencode "_csrf=$t" "$base/login"
}

# Same as form_login, but reports where the login sent you rather than the status.
form_login_location() {
  local base=$1 jar=$4 t
  t=$(curl -s -c "$jar" "$base/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
  curl -s -b "$jar" -c "$jar" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "username=$2" --data-urlencode "password=$3" --data-urlencode "_csrf=$t" "$base/login"
}

section "openldap — the directory itself"
POD=$(kubectl -n "${NAMESPACE:-uniauth}" get pod -l app=openldap -o jsonpath='{.items[0].metadata.name}')
R=$(kubectl -n "${NAMESPACE:-uniauth}" exec "$POD" -- ldapwhoami -x -D "uid=bob,ou=people,dc=example,dc=com" -w bobspassword 2>&1)
check "bob can bind" "$R" "dn:uid=bob"
R=$(kubectl -n "${NAMESPACE:-uniauth}" exec "$POD" -- ldapsearch -x -LLL -D "cn=admin,dc=example,dc=com" -w admin-pass \
      -b "ou=groups,dc=example,dc=com" "(member=uid=bob,ou=people,dc=example,dc=com)" cn 2>&1)
check "manager bind resolves bob's groups" "$R" "cn: developers"
R=$(kubectl -n "${NAMESPACE:-uniauth}" exec "$POD" -- ldapsearch -x -LLL -b "dc=example,dc=com" dn 2>&1)
check "anonymous search is refused (ACL is real)" "$R" "No such object"

section "webapp — $WEBAPP"
check "landing page is public" "$(curl -s -o /dev/null -w '%{http_code}' $WEBAPP/)" "200"
check "explainer is public"    "$(curl -s -o /dev/null -w '%{http_code}' $WEBAPP/how-it-works)" "200"
check "dashboard needs a session" "$(curl -s -o /dev/null -w '%{redirect_url}' $WEBAPP/dashboard)" "/login"
CHOOSER=$(curl -s $WEBAPP/login)
check "chooser offers the internal store" "$CHOOSER" "Local account"
check "chooser offers the directory"      "$CHOOSER" "Directory account"
check "chooser offers the provider"       "$CHOOSER" "Local OAuth"
check "provider link points at its own entry point" "$CHOOSER" "/oauth2/authorization/local"

J=$(mktemp); form_login $WEBAPP alice s3cret "$J" >/dev/null
check "alice (internal) reaches the dashboard" "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' $WEBAPP/dashboard)" "200"
# A successful sign-in used to land on the PUBLIC overview, which says nothing about
# having authenticated — the one moment confirmation matters most.
check "a sign-in lands on the page that reports it" \
  "$(form_login_location $WEBAPP alice s3cret "$(mktemp)")" "/dashboard"
check "alice sees the approvals queue (ROLE_ADMIN)" "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' $WEBAPP/approvals)" "200"

# Establish the state rather than assume it. The approval store is in memory, so a pod
# restart puts bob back in the queue — and a suite that assumed he was already approved
# reported four failures for what is documented behaviour of InMemoryApprovalStore.
J2=$(mktemp); form_login $WEBAPP bob bobspassword "$J2" >/dev/null   # records him pending
APPROVE=$(mktemp); form_login $WEBAPP alice s3cret "$APPROVE" >/dev/null
CSRF=$(curl -s -b "$APPROVE" -c "$APPROVE" $WEBAPP/approvals \
  | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
curl -s -b "$APPROVE" -c "$APPROVE" -o /dev/null \
  --data-urlencode "provider=ldap" --data-urlencode "principal=bob" \
  --data-urlencode "outcome=APPROVED" --data-urlencode "_csrf=$CSRF" $WEBAPP/approvals
check "an administrator can approve a held account" \
  "$(curl -s -b "$J2" -o /dev/null -w '%{http_code}' $WEBAPP/dashboard)" "200"
# The dashboard is the one page that reports the session; /session was folded into it.
BOBPAGE=$(curl -s -b "$J2" $WEBAPP/dashboard)
check "bob (LDAP) carries his directory DN" "$BOBPAGE" "uid=bob,ou=people,dc=example,dc=com"
check "the dashboard states the outcome"    "$BOBPAGE" "Authentication succeeded"
check "  ...and names who admitted him"     "$BOBPAGE" "admitted you"
check "the old /session URL redirects"      "$(curl -s -b "$J2" -o /dev/null -w '%{redirect_url}' $WEBAPP/session)" "/dashboard"

J3=$(mktemp); form_login $WEBAPP breakglass local-only "$J3" >/dev/null
check "breakglass (local, beside the directory) works" \
  "$(curl -s -b "$J3" -o /dev/null -w '%{http_code}' $WEBAPP/dashboard)" "200"

check "bad password is refused" "$(form_login $WEBAPP alice wrong "$(mktemp)")" "302"
J4=$(mktemp); form_login $WEBAPP alice wrong "$J4" >/dev/null
check "  ...and leaves no session" "$(curl -s -b "$J4" -o /dev/null -w '%{redirect_url}' $WEBAPP/dashboard)" "/login"

check "session cookie is app-specific (not JSESSIONID)" "$(grep -o 'WEBAPPSESSION' $J | head -1)" "WEBAPPSESSION"
check "actuator is NOT on the public port" "$(curl -s -o /dev/null -w '%{http_code}' $WEBAPP/actuator/health)" "404"

# Google, when the google profile is on. Skipped rather than failed otherwise: the button
# is configuration, and an example without credentials is correctly not offering it.
if printf '%s' "$CHOOSER" | grep -q '/oauth2/authorization/google'; then
  section "webapp -> Google"
  GLOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$WEBAPP/oauth2/authorization/google")
  check "the chooser offers Google"        "$CHOOSER" "/oauth2/authorization/google"
  check "it redirects to accounts.google" "$GLOC" "accounts.google.com/o/oauth2/v2/auth"
  check "asking for the openid scope"     "$GLOC" "scope=openid"
  check "with PKCE"                       "$GLOC" "code_challenge"
  # Google rejects http for anything that is not localhost, so the registered URI is
  # https — and a browser arriving over http would send one Google has never seen.
  check "redirect_uri is the HTTPS callback" "$GLOC" "redirect_uri=https://"
else
  printf '\n\033[1mwebapp -> Google\033[0m\n  \033[33mSKIP\033[0m google profile is off\n'
fi

# GitHub, when the github profile is on. Note what is NOT checked: whether the callback
# is registered on the OAuth App. GitHub defers that validation until after sign-in — it
# serves its login page even for a deliberately invalid redirect_uri — so the only way to
# confirm it is to complete a login by hand.
if printf '%s' "$CHOOSER" | grep -q '/oauth2/authorization/github'; then
  section "webapp -> GitHub"
  HLOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$WEBAPP/oauth2/authorization/github")
  check "the chooser offers GitHub"          "$CHOOSER" "/oauth2/authorization/github"
  check "it redirects to github.com"         "$HLOC" "github.com/login/oauth/authorize"
  # Without user:email GitHub returns no address at all, leaving an approval row with
  # nothing but a username to judge.
  check "asking for user:email"              "$HLOC" "user:email"
  check "redirect_uri is the HTTPS callback" "$HLOC" "redirect_uri=https://"
  # GitHub is plain OAuth2. If this ever reports OIDC, the demo has lost the one
  # provider that makes the distinction visible.
  check "GitHub is reported as plain OAuth2, not OIDC" \
    "$(curl -s $WEBAPP/uniauth/providers | tr '}' '\n' | grep github)" '"oidc":false'
else
  printf '\n\033[1mwebapp -> GitHub\033[0m\n  \033[33mSKIP\033[0m github profile is off\n'
fi

# SAML, when the saml profile is on.
if printf '%s' "$CHOOSER" | grep -q '/saml2/authenticate/'; then
  section "webapp -> SAML"
  check "the chooser offers SAML" "$CHOOSER" "/saml2/authenticate/"
  # Not a redirect: the POST binding returns an auto-submitting form, and its action is
  # the URL the browser posts the AuthnRequest to.
  SLOC=$(curl -s "$WEBAPP/saml2/authenticate/keycloak" | grep -oE 'action="[^"]*"' | head -1)
  # The SP redirects the browser to whatever the IdP metadata advertised. If that is http,
  # the POST binding then submits the assertion from an https page to an http action and
  # the browser blocks it with a mixed-content interstitial — which a headless browser
  # submits silently, so only a real one notices. Assert the scheme rather than the flow.
  check "the AuthnRequest form posts to the IdP over HTTPS" "$SLOC" "https://"
  check "SAML is reported as SAML, not OIDC" \
    "$(curl -s $WEBAPP/uniauth/providers | tr '}' '\n' | grep saml2)" '"type":"SAML"'
  # Metadata is read once at startup, so an IdP that advertises http leaves the SP holding
  # it until the SP restarts. Check the source too, not only what the SP now believes —
  # and derive its address from the form action rather than naming a host, so this script
  # carries no deployment of its own.
  IDP_ORIGIN=$(printf '%s' "$SLOC" | sed 's|action="||;s|"||' | cut -d/ -f1-3)
  IDP=$(curl -s "$IDP_ORIGIN/realms/uniauth/protocol/saml/descriptor" 2>/dev/null)
  check "the IdP advertises HTTPS endpoints" "$IDP" 'Location="https://'
else
  printf '\n\033[1mwebapp -> SAML\033[0m\n  \033[33mSKIP\033[0m saml profile is off\n'
fi

section "webapp -> authserver — the OAuth hop across two hosts"
JO=$(mktemp)
LOC=$(curl -s -c "$JO" -o /dev/null -w '%{redirect_url}' "$WEBAPP/oauth2/authorization/local")
check "app redirects to the provider's PUBLIC host" "$LOC" "${AUTH#http://}"
check "redirect_uri is the app's ingress URL"       "$LOC" "redirect_uri=$WEBAPP"
check "PKCE challenge is present"                   "$LOC" "code_challenge"
PAGE=$(curl -s -c "$JO" -b "$JO" -L "$WEBAPP/oauth2/authorization/local")
check "provider serves its own login page" "$PAGE" "UniAuth provider"
T=$(printf '%s' "$PAGE" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
LAND=$(curl -s -c "$JO" -b "$JO" -L -w '\n%{url_effective}' \
  --data-urlencode "username=olivia" --data-urlencode "password=oauth-pass" \
  --data-urlencode "_csrf=$T" "$AUTH/login")
check "olivia lands back on the app" "$(printf '%s' "$LAND" | tail -1)" "${WEBAPP#http://}"

section "authserver — $AUTH"
DISC=$(curl -s $AUTH/.well-known/openid-configuration)
check "discovery is published" "$DISC" "authorization_endpoint"
ISS=$(printf '%s' "$DISC" | sed 's/.*"issuer":"\([^"]*\)".*/\1/')
check "issuer matches the public host" "$ISS" "${AUTH#http://}"
check "actuator is NOT on the public port" "$(curl -s -o /dev/null -w '%{http_code}' $AUTH/actuator/health)" "404"
JA=$(mktemp); form_login $AUTH olivia oauth-pass "$JA" >/dev/null
check "olivia signs in at the provider" "$(curl -s -b "$JA" -o /dev/null -w '%{http_code}' $AUTH/)" "200"
check "an app account is NOT a provider account" "$(form_login $AUTH alice s3cret "$(mktemp)")" "302"
check "provider cookie is its own" "$(grep -o 'AUTHSERVERSESSION' $JA | head -1)" "AUTHSERVERSESSION"

section "headless — $API"
check "protected route answers 401, not a redirect" "$(curl -s -o /dev/null -w '%{http_code}' $API/api/me)" "401"
JH=$(mktemp); form_login $API alice s3cret "$JH" >/dev/null
check "alice via the JSON API" "$(curl -s -b "$JH" $API/api/me)" '"name":"alice"'
JH2=$(mktemp); form_login $API bob bobspassword "$JH2" >/dev/null
check "bob's groups come from the real directory" "$(curl -s -b "$JH2" $API/api/me)" "ROLE_DEVELOPERS"
check "providers endpoint is public" "$(curl -s -o /dev/null -w '%{http_code}' $API/uniauth/providers)" "200"

section "admin console — $CONSOLE"
JC=$(mktemp)
check "console login works" "$(form_login $CONSOLE admin admin "$JC")" "302"
check "console reaches the provider store"  "$(curl -s -b "$JC" $CONSOLE/stores/provider | grep -c 'alert--error')" "0"
check "console reaches the directory store" "$(curl -s -b "$JC" $CONSOLE/stores/directory | grep -c 'alert--error')" "0"

# The console is a client of the provider it administers. Signing in that way has to work,
# and — more importantly — has to keep working only for accounts entitled to it.
LOGIN=$(curl -s $CONSOLE/login)
check "console login offers OIDC"        "$LOGIN" "/oauth2/authorization/local"
check "console login keeps the password form (break-glass)" "$LOGIN" 'name="username"'

oidc_console() { # <user> <pass> <jar> -> final status
  local jar=$3 page t
  page=$(curl -s -c "$jar" -b "$jar" -L "$CONSOLE/oauth2/authorization/local")
  t=$(printf '%s' "$page" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
  curl -s -c "$jar" -b "$jar" -L -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=$1" --data-urlencode "password=$2" --data-urlencode "_csrf=$t" "$AUTH/login"
}
check "a provider ADMIN gets into the console over OIDC" "$(oidc_console oscar oscar-pass "$(mktemp)")" "200"
# Authenticated and refused is the correct outcome, and a different thing from a failed
# login: the provider vouched for olivia, this console simply does not admit her.
check "an ordinary provider account is refused (403, not a login failure)" \
  "$(oidc_console olivia oauth-pass "$(mktemp)")" "403"

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
