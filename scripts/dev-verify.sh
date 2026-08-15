#!/usr/bin/env bash
#
# Local pre-commit build: apply the spring-javaformat style, then run the full
# Maven verify (compile, Checkstyle, PMD, tests, JaCoCo). This mirrors what CI
# runs, so a green run here means a green run on the PR.
#
# Usage:
#   scripts/dev-verify.sh            # format + verify the whole reactor
#   scripts/dev-verify.sh -pl uniauth-spring-boot-starter -am   # extra args pass through
#
# Any arguments are forwarded to the `verify` invocation.

set -euo pipefail
cd "$(dirname "$0")/.."

# Arguments go to BOTH commands: a module that only joins the reactor under a profile
# (uniauth-examples via -Pdefault) is invisible to the formatter otherwise, and then fails
# the very validate gate this script exists to pre-empt.
echo "==> spring-javaformat:apply ${*:-(full reactor)}"
./mvnw -q spring-javaformat:apply "$@"

echo "==> verify ${*:-(full reactor)}"
./mvnw -B verify "$@"

echo "==> OK — formatted and verified"
