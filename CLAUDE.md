# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Spring Boot **starter** (`org.alexmond:uniauth-spring-boot-starter`) that puts an internal user
store, OAuth2/OIDC, SAML 2.0 and LDAP behind a **single `SecurityFilterChain`**, with a login page
that lets the user choose among whichever mechanisms are enabled.

Two modules: the starter, and `uniauth-examples` — a runnable sample app that only joins the
reactor under `-Pdefault`.

```bash
./mvnw -Pdefault -DskipTests install                    # once — publishes the starter
./mvnw -Pdefault -pl uniauth-examples spring-boot:run   # http://localhost:8080
```

The `install` is not optional (`-pl` resolves the starter from the repository, not the reactor)
and `-am` cannot replace it — that runs `spring-boot:run` against the parent too and fails on a
missing main class.

## Build & test

There is **no `mvn` on this machine** — use the wrapper, or the scripts (which are allowlisted in
`.claude/settings.json` and run without a permission prompt).

```bash
scripts/dev-verify.sh                     # format + whole-reactor verify — green here = green PR
scripts/dev-test.sh UniAuthLdapLoginTest  # targeted -Dtest run
scripts/dev-test.sh 'UniAuth*Test'        # patterns work too
./mvnw spring-javaformat:apply            # auto-format (run before committing)
```

Java 21, Spring Boot 4.1.0, Spring Security 7.0.x. CI (`.github/workflows/maven.yml`) runs
`./mvnw -B verify -Pdefault` on JDK 21 — the same gates as `dev-verify.sh`.

### Quality gates (all fail the build; the first three at `validate`)

- **spring-javaformat** 0.0.47 — **tabs**, Spring conventions. Run `:apply`; do not hand-format.
- **Checkstyle** 3.6.0 (+ Spring checks) — `checkstyle.xml` / `checkstyle-suppressions.xml` at the
  repo root, test sources included.
- **PMD** 3.28.0 — `pmd-ruleset.xml` at the repo root, `failOnViolation=true`, main sources only.
- **JaCoCo** 0.8.14 — BUNDLE line coverage ≥ **80%** at `verify`. Report at
  `uniauth-spring-boot-starter/target/site/jacoco/`.

Lint rules that bit during the scaffold: **SpringLambda** wants parenthesized single lambda params
(`(form) -> …`); **SpringTernary** wants `(a != b) ? x : y`; **AnnotationUseStyle** forbids a
trailing comma in annotation arrays; **RedundantFieldInitializer** rejects `= false` on a boolean.
Tests are named `*Test` (the sibling convention), which is why `SpringTestFileName` — it wants
`*Tests` — is suppressed.

**The Shibboleth repository is mandatory.** OpenSAML, pulled in by
`spring-security-saml2-service-provider`, is not on Maven Central. It is declared in the parent POM
and called out in the README — a bare Central-only build fails to resolve `org.opensaml:*`.

## Architecture

Everything lives under `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/`.

**One chain, not four.** `UniAuthAutoConfiguration#uniAuthSecurityFilterChain` installs form login,
OAuth2 login and SAML login onto a single `SecurityFilterChain`. Do not "simplify" this into one
chain per mechanism — chains match in order and the first match wins, so the others would never
run. The split that matters is a different one:

- **Form-based (internal, LDAP)** — share one username/password form, told apart by the
  `AuthenticationProvider` chain. Every `AuthenticationProvider` bean is registered onto the chain
  via `authenticationProviders.orderedStream().forEach(http::authenticationProvider)`, so Spring
  Security tries each until one authenticates. This is what lets local break-glass accounts sit
  alongside a directory.
- **Redirect-based (OAuth2, SAML)** — keep their own entry-point URLs
  (`/oauth2/authorization/{id}`, `/saml2/authenticate/{id}`), so the chooser just renders a link.

`AuthProviderType` encodes which half a mechanism belongs to via its `formBased` flag.

**OAuth2 and SAML config is deliberately not re-declared.** `UniAuthProperties` exposes only an
`enabled` flag for those two. Registrations come from Spring Boot's own
`spring.security.oauth2.client.registration.*` and `spring.security.saml2.relyingparty.*` binding;
UniAuth consumes the resulting repositories. Don't add registration properties under `uniauth.*` —
it would fork a large, already-documented configuration surface.

**`AuthProviderRegistry`** is the single answer to "what can a user sign in with right now", read by
both the chooser page and `/uniauth/providers`. It enumerates OAuth2/SAML entries by testing the
repository for `Iterable` — which the in-memory implementations Boot produces are. A custom
repository (database-backed, say) is not iterable, so its mechanism still works in the chain but
cannot be listed; that limitation is documented on the class.

**Conditionals.** Every bean is `@ConditionalOnMissingBean`, so an app overrides by declaring its
own rather than excluding the auto-configuration. `uniauth.enabled=false` backs off entirely.

### Brand is not a mechanism

`AuthProviderType` is the *mechanism* axis — how a provider talks, and therefore which filter
installs it. Brand (`AuthProviderBrand`) is a separate attribute, and the two must not be merged:
adding GOOGLE/MICROSOFT as peers of OAUTH2 would break the form/redirect dichotomy the filter
chain depends on, and grow without bound.

The distinction that actually changes behaviour is **OIDC vs plain OAuth2**, carried by
`AuthProvider.oidc()` (derived from the `openid` scope). Google yields an `OidcUser` with claims;
GitHub yields a bare `OAuth2User`. Brand is for icons and vendor-mandated button treatment only —
reach for `oidc()` whenever you mean capability.

Provider quirks ship as **opt-in adapters** in `Oauth2AdaptersConfiguration`, never as new types:

- `uniauth.oauth2.github.fetch-email` → `GithubEmailOAuth2UserService`, adding the `/user/emails`
  call GitHub requires before any email exists.
- `uniauth.oauth2.microsoft.multi-tenant` → `MicrosoftMultiTenantIdTokenValidator`.

That validator is security-sensitive; read its javadoc before touching it. It does **not**
reimplement id_token validation — it hands Spring's `OidcIdTokenValidator` a registration copy
with the issuer removed (Spring skips its issuer check when that is null), keeping every other
check intact, then adds the tenant-template issuer rule itself. It also checks the issuer
*before* delegating, because reading an unparseable `iss` throws and the delegate reads it first.

**Apple is unsupported** and should stay that way until Spring supports a non-static client
secret: Apple requires a generated ES256 JWT and `ClientRegistration.Builder` takes only a string.

### The sample app (`uniauth-examples`)

Design direction is a **patch panel**: providers are labelled ports, and the one that
authenticated you shows a lit brass jack with a cable dropping to the bus. It is driven by real
state — `AuthProviderRegistry` supplies the ports, and `SessionFactsResolver` works out which
one answered. Keep it that way; the panel is meant to be an instrument, not an illustration.

`SessionFactsResolver` reads the mechanism off the concrete `Authentication` types, because
nothing records it directly. OAuth2 and SAML have their own token classes; internal and LDAP
both produce `UsernamePasswordAuthenticationToken` and are told apart by whether the principal
is an `LdapUserDetails`. It lives in the sample, not the starter — promoting it would widen the
library's API before anything depends on it.

`templates/uniauth/login.html` in the sample **overrides the starter's own login template**.
That is deliberate: it demonstrates the supported re-skin path (an app's templates precede the
starter jar on the classpath) and doubles as the app's own styling.

### Two traps already hit here

- **Never let the starter's `@Controller` classes be component-scanned.** They are registered as
  `@Bean`s by the auto-configuration. The test app therefore lives in `org.alexmond.uniauth.testapp`,
  *outside* the starter's package — when it sat at `org.alexmond.uniauth` its scan picked the
  controllers up directly and bypassed both the `@Bean` methods and the `uniauth.enabled` guard.
  `UniAuthDisabledTests` is the regression guard.
- **The LDAP context source is qualified, not resolved by type.** Boot's own `LdapAutoConfiguration`
  publishes a `BaseLdapPathContextSource` bound to `spring.ldap.*`; without the
  `@Qualifier("uniAuthLdapContextSource")` a plain `@ConditionalOnMissingBean` would back off and
  silently ignore `uniauth.ldap.url`.

## Testing

`UniAuthLdapLoginTest` runs against an **embedded UnboundID directory** (Boot's
`spring.ldap.embedded.*`, fixture at `src/test/resources/test-directory.ldif`, fixed port 13389) with
the internal store enabled at the same time — that combination is what proves the provider chain
falls through. Integration tests pin the app class explicitly:
`@SpringBootTest(classes = TestApplication.class)`.

## Boot 4 gotchas

Boot 4 relocated things; verify against the jars rather than assuming 3.x layout.
`@AutoConfigureMockMvc` moved to `org.springframework.boot.webmvc.test.autoconfigure` in the
**separate `spring-boot-webmvc-test` artifact** — `spring-boot-starter-test` no longer brings it.

## House conventions (org.alexmond Spring Boot extensions)

Reference implementation: `~/IdeaProjects/spring-boot-config-json-schema`.

- **Branching** — one long-lived branch per maintained Boot minor (`3.5`, `4.0`, …); `master`
  tracks the current Boot release (4.1 today). When Boot ships a new minor, `master` rolls forward
  and the outgoing line is cut to its own branch.
- **Versioning** — the project version tracks the Boot version it builds against
  (`4.1.0.1-SNAPSHOT` → Boot 4.1.0), 4th segment being this library's own patch counter. The global
  numeric-only release rule does not apply here.
- **Publishing** — Maven Central via `-Prelease` (GPG signing + sources/javadoc), driven by
  `.github/workflows/maven_release.yml` (`workflow_dispatch` with release + next versions). Never
  run that profile locally without signing keys. Docs are an Antora site under `docs/` published to
  the alexmond.org hub; see the `release-prep` and `update-docs-hub` skills.
- **Shared config files** — `checkstyle.xml`, `checkstyle-suppressions.xml`, `pmd-ruleset.xml`,
  `.editorconfig`, `lombok.config` and `scripts/dev-*.sh` are near-identical across the sibling
  repos (unitrack, notify4j, jvmlens, kweblens, gotmpl4j, jhelm). Port fixes sideways rather than
  diverging.
- **`lab-scan.yml`** gates new lab-internal references. It self-skips until the `LAB_DENY_PATTERNS`
  repo secret is set — arming it is infra work, so file a Forgejo ticket.

## Repo-specific cautions

- **Never commit real IdP metadata, client secrets, keystores, or LDAP bind credentials.** Sample
  config uses placeholder issuers and `{noop}` passwords. `.gitignore` already blocks `*.jks`,
  `*.p12`, `*.pem`, `*.key` and `application-local.*`.
- If SAML/LDAP/OIDC config ever points at the home lab (internal DNS, RFC1918 IPs), it must not be
  committed — this repo is GitHub-bound. Use `lab-leak-guard`; keep lab values in a private overlay.
