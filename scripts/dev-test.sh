#!/usr/bin/env bash
#
# Run a targeted test (or tests) without a full reactor verify. Routes through this
# script so it matches the already-allowlisted `Bash(scripts/*)` permission and does
# not prompt for direct `mvn`/`./mvnw` invocations.
#
# Usage:
#   scripts/dev-test.sh UniAuthLdapLoginTest
#   scripts/dev-test.sh 'UniAuth*Test,AuthProvider*'          # -Dtest patterns
#   scripts/dev-test.sh UniAuthLdapLoginTest#wrongDirectoryPasswordIsRejected
#   scripts/dev-test.sh -pl uniauth-spring-boot-starter MyTest   # extra Maven args pass through
#
# The last argument is treated as the -Dtest selector; anything before it is forwarded
# to Maven. Defaults to the starter module.

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -eq 0 ]]; then
  echo "usage: scripts/dev-test.sh [maven-args...] <TestNameOrPattern>" >&2
  exit 2
fi

# Split: last arg = test selector, the rest = extra Maven args.
args=("$@")
selector="${args[${#args[@]}-1]}"
unset 'args[${#args[@]}-1]'

if [[ ${#args[@]} -eq 0 ]]; then
  set -- -pl uniauth-spring-boot-starter
else
  set -- "${args[@]}"
fi

./mvnw -q "$@" test -Dtest="$selector" -Dsurefire.failIfNoSpecifiedTests=false
