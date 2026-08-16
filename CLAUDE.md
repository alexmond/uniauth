# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Spring Boot **starter** (`org.alexmond:uniauth-spring-boot-starter`) that puts an internal user
store, OAuth2/OIDC, SAML 2.0 and LDAP behind a **single `SecurityFilterChain`**, with a login page
that lets the user choose among whichever mechanisms are enabled.

Layout: the starter, plus `uniauth-examples` — an **aggregator** (`packaging: pom`) whose
submodules only join the reactor under `-Pdefault`.

```
uniauth-spring-boot-starter/   the library — an auth CLIENT, nothing else
uniauth-authserver/            the OAuth2/OIDC provider, its own service
uniauth-admin/                 standalone console, an app not a library (skipPublishing)
uniauth-examples/              aggregator, skipPublishing=true
  webapp/                      uniauth-example-webapp   — server-rendered, start here
  headless/                    uniauth-example-headless — API-first, 401 not redirect
```

New examples go under `uniauth-examples/` as short directory names with
`uniauth-example-<name>` artifact ids, matching `gotmpl4j-samples`. **`skipPublishing` is set on
the aggregator and must stay there** — without it a release pushes demo applications to Maven
Central.

```bash
./mvnw -Pdefault -DskipTests install                              # once — publishes the starter
./mvnw -Pdefault -pl uniauth-examples/webapp spring-boot:run      # http://localhost:8080
```

Both examples deploy from the same chart via `scripts/deploy-k8s.sh --example <name>`, as two
Helm releases in one namespace (`uniauth` and `uniauth-api`) — a shared release name would have
the second clobber the first. **Every example needs `spring-boot-starter-actuator` and the `k8s`
profile**, or no management port opens and the pod never goes Ready; both examples hit this.

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

### Approval gate

`uniauth.approval.enabled` inserts a gate between authenticating and being let in. It is the
**only stateful thing in the library**, and that state lives behind the `ApprovalStore` SPI on
purpose — owning a table would force Spring Data, a schema and migrations onto every consumer.
`InMemoryApprovalStore` is the default and is not production-fit; say so rather than quietly
letting someone ship it.

Three decisions worth not re-litigating:

- **It sits in authorization, not authentication.** `ApprovalAuthorizationManager` replaces
  `.authenticated()` in the chain. Failing the login instead would report "pending" as a
  credentials failure — misleading, and it confirms a correct guess to an attacker.
- **First sighting is recorded in the manager, not a success handler.** Four mechanisms means
  four success handlers; every request passes authorization exactly once.
- **Keys are `(provider, principal)`.** Approving "alice" from the internal store must not admit
  "alice" from Google.

Two things that will bite if changed carelessly: the pending page is added to the permitted
matchers, without which the redirect loops; and `PendingApprovalAccessDeniedHandler` only
redirects requests flagged by the manager, so a genuine 403 still looks like one — a *denied*
principal gets 403, not the waiting page.

`MechanismResolver` moved from the sample into the starter here, since approval needs to know
which provider answered. That is the rule: promote when something depends on it, not before.

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

### Environment variables REPLACE a list, they do not merge into it

Bit twice in one deploy, so it is written down. Binding `console.targets[0].token` from a
Secret discards every other field of `targets[0]` that came from `application.yaml` — the
higher-priority source wins the whole collection. Same for `uniauth.internal.users[0]`.

**When any field of a list entry comes from the environment, supply all of them.**
`ManagedApplication.validate()` now fails at startup rather than letting it surface as an NPE
on the first request.

Related: an app whose `server.port` differs from the chart's 8080 goes **Ready and
unreachable** — the probes target the management port, so only the ingress notices, with a
502. The console had this at 8090.

### The admin console administers SERVICES, not applications

`uniauth-admin` owns no user store. It administers the two populations that exist
independently of any application and survive a restart:

- **the provider's accounts** — over `uniauth-authserver`'s token-authenticated admin API;
- **the directory** — over LDAP, written directly.

It used to administer running UniAuth *applications*, over an admin API the starter
published. Both halves of that were wrong. The API had no business in an authentication
library, and the accounts it reached lived in an application's memory, so "administering"
them meant editing something that vanished on the next restart. When the starter's API was
removed the console kept pointing at it and every page showed `no suitable
HttpMessageConverter` — the app was answering with its login page, because the endpoint was
gone.

Both stores sit behind a console-local `UserStore` SPI (`store/`). Keep that interface
small: the two backends have almost nothing in common, and widening it means inventing a
lowest common denominator neither side has.

- **Roles are editable at the provider, not in the directory.** A directory group is an
  entry with its own members, not a field on a person — the applications resolve roles by
  *searching* those groups. `supportsRoles()` carries this, and the template hides the
  column.
- **JNDI's `unbind` is idempotent**: it succeeds when the entry does not exist. Deleting an
  absent user therefore reported "Removed ghost." having removed nothing — a false
  confirmation, worse than an error. `DirectoryUserStore#delete` looks the entry up first.
- **A store that is switched off contributes no bean**, so the console lists exactly what it
  can reach rather than offering something that fails on the first click.

#### The console signs in with OIDC, and that closes a loop on purpose

The console is a client of the provider it administers, so its login page offers the same
choice every other service here does instead of being the one box that only takes a local
password. Two pieces make it work, and neither is optional:

- **`RolesClaimTokenCustomizer`** (provider) puts the account's authorities into the ID
  token as `roles`. Without it an OIDC login arrives with `OIDC_USER` and `SCOPE_*` and no
  roles, so every console page 403s — a working sign-in that reaches nothing, which reads
  as a broken console rather than a permissions decision.
- **`ConsoleAuthoritiesMapper`** (console) maps that claim back to authorities. It honours
  only `ROLE_`-prefixed values, so a provider cannot name an authority of its own choosing.

The console is a **separate client** at the provider (`uniauth-admin`), not a second
redirect-uri on the demo's — sharing one would let either application be sent to the
other's callback.

**The loop is real and deliberate.** The console holds a token that creates provider
accounts, including `ROLE_ADMIN` ones, so admitting provider administrators here means a
provider administrator can administer the provider. Fine when both are the same operator,
wrong wherever the two populations are meant to be separate; there, disable the
registration or key on a claim the provider's own admins cannot grant themselves. The
local `admin` account stays as break-glass for when the provider is down.
- **The provider's API refuses to start without a token**, compares it with
  `MessageDigest.isEqual` (a plain `equals` leaks the credential a character at a time to
  anyone who can measure the response), and runs on a stateless CSRF-disabled chain ahead of
  the browser one — a console has no session to ride and must never be redirected to a login
  page.

### Deployments are `Recreate`, because the state is in the pod

Sessions and the approval queue live in memory. A `RollingUpdate` overlaps two pods, so a
principal approved on one is still pending on the other and a session established on one is
unknown to the other — which showed up three times as a handful of post-deploy failures that
passed on the next run. `updateStrategy: Recreate` in the overlays trades a few seconds of
downtime for state that does not fork. It is not a fix for the underlying limitation:
`InMemoryApprovalStore` still empties on restart, and a real deployment supplies its own.

### Verify a deployment by using it, not by reading `kubectl get pods`

`scripts/verify-deployment.sh` and `scripts/verify-console.sh` exercise the deployed
configuration through the paths a user takes; hostnames come from the environment, so the
repo carries no domain of its own.

```bash
WEBAPP=http://… API=http://… AUTH=http://… CONSOLE=http://… scripts/verify-deployment.sh
```

Ready proves only that the management port answers. Every deployment failure in this repo so
far — a 502 from a port mismatch, a console pointed at a removed API, a provider 404ing its
own root, a template needing a dialect that is not on the classpath — passed the probes. The
console checks go further and confirm the effect on the *other* side: an account created
through the console must actually sign in at the provider, and one created in the directory
must sign in to the web app.

### Cookies are scoped by HOST, not by port

Two Spring services on `localhost:8080` and `localhost:9000` share one `JSESSIONID` and each
overwrites the other's session. In an OAuth redirect that is fatal and nearly invisible: the
provider's cookie replaces the client's, the client returns to a session with no saved
authorization request, and the login dies with a redirect to `?error` and **nothing logged**.

Every service here therefore sets its own `server.servlet.session.cookie.name`. Do not remove
them, and set one on any new service that will run beside these.

### The provider is its own service (was: hosted by the example)

`uniauth-authserver` is the OAuth2/OIDC provider, and it does **not** depend on the starter —
a provider is not a client of one, and pulling the starter in would put a provider chooser and
an approval gate on an identity server.

It used to be co-hosted inside the webapp example, which worked only by giving each chain its
own `SecurityContextRepository` so the two logins could not see each other. Separate processes
have separate sessions, so that machinery is gone. If you are ever tempted to co-host them
again, that is what it costs.

Its accounts are its own, administered through its own token-authenticated admin API — which is
where such an API belongs, rather than inside a client library.

### The directory is its own service too (was: embedded in the example)

The examples used to run Boot's `spring.ldap.embedded` UnboundID server in-process. That is a
**test fixture**, and it is now scoped as one: `unboundid-ldapsdk` is `<scope>test</scope>`, the
embedded server is declared in `src/test/resources/application.yaml`, and the applications
themselves only know `uniauth.ldap.url`. The lab runs OpenLDAP (`osixia/openldap:1.5.0`,
manifests in the private `uniauth-deploy` overlay).

Two things bite the moment the directory is real, and neither shows up against the embedded one:

- **A real directory is not world-readable.** OpenLDAP's default ACL is `by self read … by * none`,
  and a denied search returns **`no such object` (32)**, not "permission denied" — it will not
  admit the entry exists. bob authenticates and then comes back with no groups. The fix is a bind
  account: `uniauth.ldap.manager-dn` / `manager-password`, which the authorities populator uses
  for the group search.
- **Mount a bootstrap LDIF with `subPath`.** A whole-directory ConfigMap mount plants a `..data`
  symlink tree beside the file, osixia's bootstrap `find`s both copies, and the second pass dies
  with **status 68 (already exists)** on a database that was empty a second ago.

### Two extension points, before you replace the chain

Declaring your own `SecurityFilterChain` makes the whole starter back off, so these exist to
avoid that — and each was added because an example needed it, never speculatively:

- `uniauth.public-paths` — open up routes (the webapp example needed public pages).
- An `AuthenticationEntryPoint` bean — the starter uses it instead of redirecting to the
  chooser (the headless example needed 401).
- **A second `SecurityFilterChain`** — the catch-all now backs off on its own bean *name*
  (`uniAuthSecurityFilterChain`), not on the type, so adding a chain no longer costs you every
  mechanism. The local OAuth provider needed this.

That is the pattern to keep following: build the example first, and let it prove the gap.

### The sample app (`uniauth-examples/webapp`)

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

**Never put an `application.yaml` in an example's `src/test/resources`.** Boot resolves
`classpath:/application.yaml` to the *first* match, and `target/test-classes` precedes
`target/classes`, so it does not add to the application's configuration — it replaces it
outright, taking the internal accounts, public paths and approval gate with it. The tests then
fail on a missing `ApprovalStore` bean, which points nowhere near the actual cause. Test
overrides go in `application-test.yaml` with `@ActiveProfiles("test")`; a profile document
overlays the base file instead of shadowing it.

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
