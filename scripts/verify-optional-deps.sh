#!/usr/bin/env bash
#
# Proves the starter's optional dependencies really are optional, from the outside.
#
# LDAP and SAML are marked <optional>true</optional> so a consumer does not inherit them.
# That is easy to assert and easy to break: nothing in this repo's own build notices, because
# the reactor has both jars and the Shibboleth repository on hand. It has already broken once
# — LDAP was made optional and SAML was left behind, and a consumer found it, not CI.
#
# So this generates a throwaway consumer with NO <repositories> at all, resolves it against
# Maven Central alone, and boots it. Two failures it catches that a unit test cannot:
#
#   * a dependency that slipped back to compile scope — it appears in the tree, and for SAML
#     the build cannot even resolve org.opensaml:* without the Shibboleth repository;
#   * a general class naming an absent type — the context fails with NoClassDefFoundError on
#     the first request, or at startup.
#
# Usage: scripts/verify-optional-deps.sh   (installs the starter first; ~2 minutes)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MVNW="$REPO/mvnw"
WORK="$(mktemp -d)"
PORT=18099
PID=""
FAILURES=0

cleanup() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

VERSION="$("$MVNW" -q -B -f "$REPO/pom.xml" help:evaluate -Dexpression=project.version -DforceStdout)"
echo "Verifying optional dependencies of uniauth-spring-boot-starter $VERSION"

echo "==> installing the starter"
"$MVNW" -q -B -f "$REPO/pom.xml" -pl uniauth-spring-boot-starter -DskipTests -Djacoco.skip=true install

mkdir -p "$WORK/src/main/java/probe" "$WORK/src/main/resources"
cat > "$WORK/pom.xml" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>4.1.0</version>
        <relativePath/>
    </parent>
    <groupId>probe</groupId>
    <artifactId>uniauth-optional-deps-probe</artifactId>
    <version>1.0.0</version>
    <properties><java.version>21</java.version></properties>
    <!-- No <repositories>: Maven Central only. That is the whole point. -->
    <dependencies>
        <dependency>
            <groupId>org.alexmond</groupId>
            <artifactId>uniauth-spring-boot-starter</artifactId>
            <version>$VERSION</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
EOF

cat > "$WORK/src/main/java/probe/ProbeApplication.java" <<'EOF'
package probe;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ProbeApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProbeApplication.class, args);
	}

}
EOF

# OAuth2 and the internal store are both switched on: the point is that the mechanisms that
# survive still work, not merely that the context starts with everything off.
cat > "$WORK/src/main/resources/application.yaml" <<EOF
server:
  port: $PORT
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: probe
            client-secret: probe
uniauth:
  enabled: true
  internal:
    enabled: true
    users:
      - username: alice
        password: "{noop}s3cret"
        roles: [ USER ]
  approval:
    enabled: true
EOF

echo "==> resolving against Maven Central only"
"$MVNW" -q -B -f "$WORK/pom.xml" dependency:tree -DoutputFile="$WORK/tree.txt" -DappendOutput=false >/dev/null

for absent in opensaml saml2 spring-security-ldap spring-boot-starter-ldap; do
	if grep -qi "$absent" "$WORK/tree.txt"; then
		fail "$absent is on a consumer's classpath (should be optional)"
		grep -i "$absent" "$WORK/tree.txt" | sed 's/^/        /'
	else
		pass "$absent absent from the consumer's dependency tree"
	fi
done

echo "==> booting the consumer"
"$MVNW" -q -B -f "$WORK/pom.xml" package -DskipTests >/dev/null
java -jar "$WORK/target/uniauth-optional-deps-probe-1.0.0.jar" > "$WORK/app.log" 2>&1 &
PID=$!

for _ in $(seq 1 90); do
	curl -sf -o /dev/null "http://localhost:$PORT/uniauth/providers" && break
	sleep 1
done

if curl -sf -o "$WORK/providers.json" "http://localhost:$PORT/uniauth/providers"; then
	pass "the context starts and serves the providers endpoint"
else
	fail "the context did not start — see below"
	tail -40 "$WORK/app.log" | sed 's/^/        /'
fi

# The chain has to have installed the mechanisms that ARE present, not just avoided the ones
# that are not: a NoClassDefFoundError swallowed into a backed-off bean would look the same
# as a healthy start otherwise.
if grep -q '"id":"google"' "$WORK/providers.json" 2>/dev/null; then
	pass "OAuth2 still enumerates without the SAML jars"
else
	fail "OAuth2 registrations are missing from the chooser"
fi
if grep -q '"id":"internal"' "$WORK/providers.json" 2>/dev/null; then
	pass "the internal store still enumerates"
else
	fail "the internal store is missing from the chooser"
fi

COOKIES="$WORK/cookies"
CSRF="$(curl -s -c "$COOKIES" "http://localhost:$PORT/login" | grep -oP 'name="_csrf"[^>]*value="\K[^"]+' | head -1)"
STATUS="$(curl -s -b "$COOKIES" -c "$COOKIES" -o /dev/null -w '%{http_code}' \
	-d "username=alice&password=s3cret&_csrf=$CSRF" "http://localhost:$PORT/login")"
if [ "$STATUS" = "302" ]; then
	pass "a form login completes end to end"
else
	fail "form login returned $STATUS, expected 302"
	tail -30 "$WORK/app.log" | sed 's/^/        /'
fi

if grep -qE "NoClassDefFoundError|ClassNotFoundException" "$WORK/app.log"; then
	fail "a missing class surfaced at runtime"
	grep -E "NoClassDefFoundError|ClassNotFoundException" "$WORK/app.log" | head -5 | sed 's/^/        /'
else
	pass "no NoClassDefFoundError or ClassNotFoundException in the log"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
	echo "==> OK — LDAP and SAML are genuinely optional"
else
	echo "==> $FAILURES check(s) failed"
	exit 1
fi
