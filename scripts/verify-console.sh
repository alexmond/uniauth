#!/usr/bin/env bash
#
# Usage:
#   WEBAPP=http://... API=http://... AUTH=http://... CONSOLE=http://... \
#     scripts/verify-console.sh
#
# Hostnames come from the environment: they are deployment facts, and this repo carries no
# domain of its own.
# Exercises the deployed console's CRUD against both real stores, then proves the effect
# from the OTHER side — an account created here must actually be able to sign in.

CONSOLE=${CONSOLE:?set CONSOLE}
AUTH=${AUTH:?set AUTH}
WEBAPP=${WEBAPP:?set WEBAPP, e.g. http://uniauth.example.com}

PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; printf '       %s\n' "$2"; FAIL=$((FAIL+1)); }
check(){ case "$2" in *"$3"*) ok "$1";; *) bad "$1" "expected '$3', got: $(printf '%s' "$2" | tr -d '\n' | cut -c1-220)";; esac }
section(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

J=$(mktemp)
csrf() { curl -s -b "$J" -c "$J" "$1" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }

# console sign-in
T=$(curl -s -c "$J" "$CONSOLE/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
curl -s -b "$J" -c "$J" -o /dev/null --data-urlencode "username=admin" --data-urlencode "password=admin" \
  --data-urlencode "_csrf=$T" "$CONSOLE/login"

# post <path> <form fields...>  — refetches CSRF from the store page each time
post() {
  local path=$1; shift
  local t; t=$(csrf "$CONSOLE/stores/${path%%/*}")
  local args=(); for f in "$@"; do args+=(--data-urlencode "$f"); done
  curl -s -b "$J" -c "$J" -L "${args[@]}" --data-urlencode "_csrf=$t" "$CONSOLE/stores/$path"
}

section "console lists what it can actually reach"
INDEX=$(curl -s -b "$J" "$CONSOLE/")
check "provider store is offered"  "$INDEX" "/stores/provider"
check "directory store is offered" "$INDEX" "/stores/directory"

section "provider store — over the admin API"
P=$(curl -s -b "$J" "$CONSOLE/stores/provider")
check "reads the provider's accounts"      "$P" "olivia"
check "no error banner"                    "$(printf '%s' "$P" | grep -c 'alert--error')" "0"

R=$(post "provider/users" "username=consoletest" "password=made-here" "roles=USER")
check "create reports success"             "$R" "Created consoletest"
check "and the account is listed"          "$R" "consoletest"

# The point of the whole exercise: it must work at the provider, not just appear in a table.
JP=$(mktemp)
T=$(curl -s -c "$JP" "$AUTH/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
LOC=$(curl -s -b "$JP" -c "$JP" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=consoletest" --data-urlencode "password=made-here" --data-urlencode "_csrf=$T" "$AUTH/login")
check "the created account can sign in AT THE PROVIDER" "$LOC" "$AUTH/"

R=$(post "provider/users/consoletest/password" "password=rotated")
check "password change reports success"    "$R" "Changed the password"
JP2=$(mktemp)
T=$(curl -s -c "$JP2" "$AUTH/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
LOC=$(curl -s -b "$JP2" -c "$JP2" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=consoletest" --data-urlencode "password=rotated" --data-urlencode "_csrf=$T" "$AUTH/login")
check "  ...and the NEW password works"    "$LOC" "$AUTH/"
JP3=$(mktemp)
T=$(curl -s -c "$JP3" "$AUTH/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
LOC=$(curl -s -b "$JP3" -c "$JP3" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=consoletest" --data-urlencode "password=made-here" --data-urlencode "_csrf=$T" "$AUTH/login")
check "  ...and the OLD one does not"      "$LOC" "error"

R=$(post "provider/users/consoletest/roles" "roles=USER, ADMIN")
check "roles update reports success"       "$R" "Updated the roles"

R=$(post "provider/users" "username=consoletest" "password=x" "roles=USER")
check "duplicate is refused with the provider's own message" "$R" "already an account called"

R=$(post "provider/users/consoletest/delete")
check "delete reports success"             "$R" "Removed consoletest"
P=$(curl -s -b "$J" "$CONSOLE/stores/provider")
check "  ...and the account is gone"       "$(printf '%s' "$P" | grep -c consoletest)" "0"

section "directory store — straight to LDAP"
D=$(curl -s -b "$J" "$CONSOLE/stores/directory")
check "reads the directory"                "$D" "bob"
check "shows the entry's DN"               "$D" "uid=bob,ou=people,dc=example,dc=com"
check "no error banner"                    "$(printf '%s' "$D" | grep -c 'alert--error')" "0"
check "roles are not offered here"         "$(printf '%s' "$D" | grep -c 'users/bob/roles')" "0"

R=$(post "directory/users" "username=carol" "password=carols-password")
check "create reports success"             "$R" "Created carol"

# Again: prove it in the directory, and prove the APPLICATION can use it.
POD=$(kubectl -n "${NAMESPACE:-uniauth}" get pod -l app=openldap -o jsonpath='{.items[0].metadata.name}')
R=$(kubectl -n "${NAMESPACE:-uniauth}" exec "$POD" -- ldapwhoami -x -D "uid=carol,ou=people,dc=example,dc=com" -w carols-password 2>&1)
check "the new entry binds in the directory" "$R" "dn:uid=carol"

JW=$(mktemp)
T=$(curl -s -c "$JW" "$WEBAPP/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//')
curl -s -b "$JW" -c "$JW" -o /dev/null --data-urlencode "username=carol" --data-urlencode "password=carols-password" \
  --data-urlencode "_csrf=$T" "$WEBAPP/login"
check "and carol can sign in to the WEB APP" "$(curl -s -b "$JW" -L "$WEBAPP/pending" | grep -o 'carol' | head -1)" "carol"

R=$(post "directory/users/carol/password" "password=changed-it")
check "password change reports success"    "$R" "Changed the password"
R=$(kubectl -n "${NAMESPACE:-uniauth}" exec "$POD" -- ldapwhoami -x -D "uid=carol,ou=people,dc=example,dc=com" -w changed-it 2>&1)
check "  ...and the directory accepts it"  "$R" "dn:uid=carol"

R=$(post "directory/users" "username=carol" "password=x")
check "duplicate entry is refused"         "$R" "already has an entry"

R=$(post "directory/users/carol/delete")
check "delete reports success"             "$R" "Removed carol"
R=$(kubectl -n "${NAMESPACE:-uniauth}" exec "$POD" -- ldapsearch -x -LLL -D "cn=admin,dc=example,dc=com" -w admin-pass \
      -b "ou=people,dc=example,dc=com" "(uid=carol)" dn 2>&1)
check "  ...and the entry is really gone"  "${R:-empty}" "empty"

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
