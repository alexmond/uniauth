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
check "alice sees the approvals queue (ROLE_ADMIN)" "$(curl -s -b "$J" -o /dev/null -w '%{http_code}' $WEBAPP/approvals)" "200"

J2=$(mktemp); form_login $WEBAPP bob bobspassword "$J2" >/dev/null
BOBPAGE=$(curl -s -b "$J2" $WEBAPP/session)
check "bob (LDAP) carries his directory DN" "$BOBPAGE" "uid=bob,ou=people,dc=example,dc=com"

J3=$(mktemp); form_login $WEBAPP breakglass local-only "$J3" >/dev/null
check "breakglass (local, beside the directory) works" \
  "$(curl -s -b "$J3" -o /dev/null -w '%{http_code}' $WEBAPP/dashboard)" "200"

check "bad password is refused" "$(form_login $WEBAPP alice wrong "$(mktemp)")" "302"
J4=$(mktemp); form_login $WEBAPP alice wrong "$J4" >/dev/null
check "  ...and leaves no session" "$(curl -s -b "$J4" -o /dev/null -w '%{redirect_url}' $WEBAPP/dashboard)" "/login"

check "session cookie is app-specific (not JSESSIONID)" "$(grep -o 'WEBAPPSESSION' $J | head -1)" "WEBAPPSESSION"
check "actuator is NOT on the public port" "$(curl -s -o /dev/null -w '%{http_code}' $WEBAPP/actuator/health)" "404"

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

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
