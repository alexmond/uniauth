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
uniauth-spring-boot-starter-test/  store contract suites — PUBLISHED, see below
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
scripts/verify-optional-deps.sh           # proves LDAP + SAML stay optional, from outside
./mvnw spring-javaformat:apply            # auto-format (run before committing)
```

`dev-verify.sh` takes `-Pdefault` to include the examples; without it the reactor stops at the
starter, the auth server and the admin console. `verify-optional-deps.sh` generates a Central-only
consumer and boots it — the only check that can catch an optional dependency slipping back to
compile scope, which has happened once already.

Java 21, Spring Boot 4.1.1, Spring Security 7.0.x. CI (`.github/workflows/maven.yml`) runs
`./mvnw -B verify -Pdefault` on JDK 21 — the same gates as `dev-verify.sh`.

### Quality gates (all fail the build; the first three at `validate`)

- **spring-javaformat** 0.0.47 — **tabs**, Spring conventions. Run `:apply`; do not hand-format.
- **Checkstyle** 3.6.0 (+ Spring checks) — `checkstyle.xml` / `checkstyle-suppressions.xml` at the
  repo root, test sources included.
- **PMD** 3.28.0 — `pmd-ruleset.xml` at the repo root, `failOnViolation=true`, main sources only.
- **JaCoCo** 0.8.15 — BUNDLE line coverage ≥ **80%** at `verify`. Report at
  `uniauth-spring-boot-starter/target/site/jacoco/`.

Lint rules that bit during the scaffold: **SpringLambda** wants parenthesized single lambda params
(`(form) -> …`); **SpringTernary** wants `(a != b) ? x : y`; **AnnotationUseStyle** forbids a
trailing comma in annotation arrays; **RedundantFieldInitializer** rejects `= false` on a boolean.
Tests are named `*Test` (the sibling convention), which is why `SpringTestFileName` — it wants
`*Tests` — is suppressed.

**The Shibboleth repository is mandatory *here*, and deliberately not for consumers.** OpenSAML,
needed by `spring-security-saml2-service-provider`, is not on Maven Central, so this reactor
declares the repository in the parent POM — the starter compiles against SAML even though it does
not ship it. `spring-boot-starter-security-saml2` is `<optional>true</optional>`, precisely so that
obligation stops at this repo: a consumer resolves the starter from Central alone, and only an
application that actually speaks SAML adds the dependency and the repository (README and
`getting-started.adoc` both say so). The regression to watch for is anything that makes a SAML type
loadable from a general code path — see `RedirectMechanism` below.

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

**`RedirectMechanism` is why nothing general names a SAML or OAuth2 type.** `SamlMechanism` and
`Oauth2Mechanism` (both package-private, both behind `@ConditionalOnClass` in
`RedirectMechanismConfiguration`) own their repository type, their registration type and their
`http.*Login` call; `AuthProviderRegistry` and `uniAuthSecurityFilterChain` only aggregate over the
beans. Keep it that way — the moment a general class does `instanceof Saml2Authentication` or takes
a `RelyingPartyRegistrationRepository` in a signature, the jar stops being optional and the
Shibboleth repository is back in every consumer's build. Where a type genuinely has to be read off
a principal (`MechanismResolver`, `PrincipalIdentityResolver`, `Authentications`), it goes in a
nested class guarded by `ClassUtils.isPresent` — an `instanceof` against an absent type in the
enclosing method can fail verification before the guard runs. `Oauth2MechanismTest` covers
enumeration; `AuthProviderRegistryTest` covers only aggregation and ordering, and names no
mechanism type at all, which is the property to preserve.

**`AuthProviderRegistry`** is the single answer to "what can a user sign in with right now", read by
both the chooser page and `/uniauth/providers`. Mechanisms enumerate their entries by testing the
repository for `Iterable` — which the in-memory implementations Boot produces are. A custom
repository (database-backed, say) is not iterable, so its mechanism still works in the chain but
cannot be listed; that limitation is documented on the class.

**Conditionals.** Every bean is `@ConditionalOnMissingBean`, so an app overrides by declaring its
own rather than excluding the auto-configuration. `uniauth.enabled=false` backs *this starter*
off entirely — **not the same as no security** (#33): `spring-boot-starter-security` is still
on the classpath, so Boot's own auto-configuration takes over and locks every path behind a
generated password. An application that wants to run open declares a permit-all chain of its
own. `UniAuthDisabledTest` pins both halves.

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

#### Invitations claim an account, they do not provision one

`uniauth.approval.invitations.enabled` hands a named person a one-use URL that attaches
whichever login they complete to a record the application already holds. The issue (#29)
proposed matching on the invited email address; the token in the URL replaces that, and
deletes `email_verified`, address normalisation, cross-provider matching and the disclosure
rule along with it — which is also why it works for SAML and LDAP, where email matching
could not.

Things that will bite if changed carelessly (no count here; the heading above says why):

- **The `GET` on the invitation path must stay free of side effects, and accepting must stay
  a `POST`.** A `GET` cannot carry a CSRF token, so a `GET` that stashed the invitation could
  be fired from any other site — an `img` tag is enough. It would plant that site's
  invitation in a visitor's session, and the visitor would then sign in with their own
  account and be bound to the record that invitation names, with its roles, never seeing the
  page that exists to make exactly this deliberate.

- **`redeem` is keyed by principal, not by token.** Re-claiming with the same `ApprovalKey`
  is a no-op. That is what lets a throwing listener be retried: the event is published
  *before* the approval is written, so a failure leaves the principal `PENDING` with the
  claim intact, and the next request gets them in. Making the token dead on first claim
  would strand the invited person after one transient error, with no way back except an
  administrator noticing.
- **The event goes out before `decide(APPROVED)`.** Reversing them produces
  admitted-but-unlinked — browsing as nobody, holding a session no record backs.
- **Redemption does not condition on `UNKNOWN`.** A session lost mid-login arrives
  `PENDING`, and somebody already signed in confirms on the invitation page. Conditioning on
  a first sighting breaks both.
- **The approver is recorded as `invitation:<subjectRef>`, never the token.** The token is a
  bearer credential and has no business in an audit record. `InvitationToken.toString()`
  redacts itself for the same reason.
- **Revocation, and any decision a *person* recorded, outrank the retry.** The retry window
  can be as long as an outage, which is exactly when somebody intervenes, so neither may be
  undone by it — and that includes an approver's *approval*, whose roles may be deliberately
  narrower than the invitation's. Two decisions are not a person's and so may be replaced:
  `invite-only`'s own automatic `DENIED` (under that setting every stranger is recorded
  `DENIED`, so anyone who signed in before opening their link would otherwise be locked out
  for good) and a grant an earlier invitation made (re-inviting is the only way to change
  what somebody was granted, since invitations are never reopened). That is what
  `InvitationRedemption.INVITE_ONLY` and `APPROVER_PREFIX` are for — the classes have to
  agree on what "not a person" looks like.

- **Redemption runs ahead of the `require-for` check, and must stay there.** An invitation is
  not a gate; it says who a login belongs to. `require-for` excludes INTERNAL by default, so
  behind that check an invitation completed with an internal login claimed nothing, published
  nothing and recorded no `usedBy` — while letting the person in, so nothing looked wrong to
  anybody. `UniAuthInvitationUngatedTest` is the guard, and it is the one invitation test that
  deliberately sets no `require-for`.
- **The manager puts the granted roles on the context itself.** `ApprovalAuthoritiesFilter`
  cannot: it runs before `AuthorizationFilter` — it has to, or an approver's roles arrive
  after the decision that needed them — but roles an invitation grants are created *by* that
  decision. Without it the invited person lands on their first `hasRole`-gated page, gets 403,
  and finds it works on refresh. The prefixing rule lives once, in
  `ApprovalAuthoritiesFilter.granting`.
- **The session carries the token's *text*, not the record.** spring-session-redis,
  spring-session-jdbc and Tomcat persistence all default to JDK serialization, so a
  non-serializable attribute throws when the session is saved — on the POST that accepts the
  invitation, which is the only flow this feature has. A `String` has no such contract to get
  wrong, and an unexpected attribute reads as no invitation rather than throwing on every
  request after a rolling upgrade.
- **`InvitationRedeemedEvent` is at-least-once.** Two requests on one session can both read
  the token before either clears it, and the no-op in `redeem` lets the second through, so
  both publish. Combined with "a listener that throws fails the admission", a non-idempotent
  listener turns a duplicate into a refusal of somebody who is approved. Documented on the
  event and in `invitations.adoc`; `InvitationRedemptionTest` pins the count.

`Invitation.usedBy` is why `ApprovalRecord` does not gain a `subjectRef` field: the link is
already durable, and widening that record would break every `ApprovalStore` implementor, as
#5 did once. `InvitationStore.findByUsedBy` is how that link is read back (#36) — a `default`
method over `list`, so adding it broke nobody. Two edges are contract, not convenience: the
**latest** claim wins (re-inviting leaves two invitations naming one principal), and a claim
later **revoked** is still returned, because revocation outranks use in `status()` and
filtering on `USED` would answer "holds nothing" for exactly the person whose link needs
repairing.

**`invite-only` does not lock everyone out, and the route in is a local account.**
`require-for` excludes INTERNAL, and the invite-only refusal sits *behind* that check, so an
account in `uniauth.internal.users` is admitted without being asked for an invitation — that
is who mints the first one (#35). Adding INTERNAL to `require-for` closes the door, and then
the only way in is `recordPending` followed by `decide`. Which is also why
**`ApprovalStore.decide` leaves a key it has never seen alone**: creating one would invent a
decision about somebody with no identity and no mechanism behind it, a row an approver
reading the queue cannot make sense of. That is now stated on the interface, because it was
not, and the two answers are not interchangeable to a caller.

**Rules contributed through `UniAuthAuthorizationCustomizer` run before the gate.** They have
to — the gate is the catch-all — so a rule ending in `.authenticated()` admits every account
the provider will issue, approved or not, and under `invite-only` the very people it refuses
(#34). A role is safe, because the gate is what puts an approver's roles on the principal;
`.access(approvalManager)` is the other safe ending. The docs demonstrated the unsafe one.
There is no startup warning for this and cannot easily be: Spring Security exposes no
read-back of the rules a customizer registered.

### The contract kit is a module, not a test-jar

`uniauth-spring-boot-starter-test` publishes `ApprovalStoreContract` and
`InvitationStoreContract` — suites an application's own store extends to prove it honours
the rules (#37). It is **published to Central**, so it is API: renaming a protected method
there breaks an implementor's build.

- **A module rather than a `tests` classifier on the starter**, which is what the issue
  asked for. A test-jar publishes *every* test class, so `TestApplication` and 200-odd
  internal tests would become de facto API — rename one and a consumer breaks — and their
  component scan could reach an application class meant for this repo alone.
- **The clock is a `MutableClock` the contract moves, not a second `Clock.fixed` store.**
  Carrying contents into a second store needs a seam no SPI method offers (the in-memory
  one's `put` is package-private, and widening it for test convenience is the wrong trade).
  Moving the clock keeps the store under test the same object — and catches an
  implementation that reads `clock.instant()` once in its constructor.
- **`ContractCatchesViolationsTest` is the load-bearing file.** It runs the suites against
  deliberately broken stores via `EngineTestKit` and asserts they *fail*. Without it the
  kit is unfalsifiable: passing against the two shipped implementations proves the rules
  are satisfiable and nothing about whether they are enforced. It has already earned its
  keep twice — it caught that the fixture's own `get`-then-`put` was non-atomic (so every
  variant failed the concurrency case, proving nothing about its own flaw), and it showed
  that **three of the five revocation cases still pass against a store that ignores
  `revoke`**, because they assert what revocation leaves alone. When adding a rule, add
  the broken store that violates it.
- The kit depends on the starter, so the starter can **never** depend on the kit — the
  in-memory implementations are run against the contracts from the kit's own `src/test`.

### Brand is not a mechanism

`AuthProviderType` is the *mechanism* axis — how a provider talks, and therefore which filter
installs it. Brand (`AuthProviderBrand`) is a separate attribute, and the two must not be merged:
adding GOOGLE/MICROSOFT as peers of OAUTH2 would break the form/redirect dichotomy the filter
chain depends on, and grow without bound.

The distinction that actually changes behaviour is **OIDC vs plain OAuth2**, carried by
`AuthProvider.oidc()` (derived from the `openid` scope). Google yields an `OidcUser` with claims;
GitHub yields a bare `OAuth2User`. Brand is for icons and vendor-mandated button treatment only —
reach for `oidc()` whenever you mean capability.

**The button label lives in the model, never in the template (#8).** `AuthProviderBrand`
carries each brand's mandated `callToAction()` and `AuthProvider.buttonLabel()` resolves it,
falling back to the registration's client name. Templates render `buttonLabel()`;
`displayName()` is the raw client name, which for Google is `Google` — the one rendering
Google's guidelines explicitly forbid. It has to be the model because overriding
`templates/uniauth/login.html` is the supported re-skin path and the webapp example takes
it, so compliance in the markup would be lost by exactly the apps most likely to restyle.
`GoogleProfileTest` guards that from the example's side.

Three things not to "tidy" here:

- **The labels read alike on purpose, and cannot be made identical.** The approved sets do
  not intersect — Microsoft's has no "Continue with", Facebook's has no "Sign in with" — so
  `Sign in with X` is used everywhere permitted and Facebook takes `Login with Facebook`,
  the closer of its two. `AuthProviderBrandTest` pins "exactly one brand may deviate", so
  adding a brand with its own phrasing fails that test rather than drifting silently.
- **Google's and Microsoft's marks keep their own colours; the rest switch variants.**
  Both forbid altering theirs. GitHub and Facebook publish official black *and* white
  marks, so those swap on `prefers-color-scheme` with explicit `#000000`/`#FFFFFF` —
  **not** `currentColor`, which would resolve to the near-black the text uses and so to a
  shade neither brand published.
- **Apple mandates a treatment and deliberately gets none.** Sign in with Apple cannot
  complete here at all, so a compliant button would decorate a dead end and tell the
  person the route works. Apple's rules were also the one set not read from the vendor's
  own page. Give it a treatment only alongside working support — #42 is the investigation.
- **One palette for all the buttons, and it is Google's mandated one.** Microsoft permits a
  light or dark scheme, Facebook's approved designs include white-with-black-text, GitHub
  constrains only its mark — so Google's values satisfy everyone and the column reads as
  one set. The only deviation from Google's spec is the typeface: the chooser renders before
  anybody has authenticated, so no webfont is fetched on it.

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

### Extension points, before you replace the chain

Declaring your own `SecurityFilterChain` makes the whole starter back off, so these exist to
avoid that — and each was added because an example needed it, never speculatively. Do not put
a count in this heading; it has gone stale twice.

- `uniauth.public-paths` — open up routes (the webapp example needed public pages).
- A **`UniAuthAuthorizationCustomizer`** bean — contributes authorization rules to the one
  chain, applied after the permitted paths and before the catch-all, for rules that are not
  shaped like "permitted or authenticated" (#3).
- An `AuthenticationEntryPoint` bean — the starter uses it instead of redirecting to the
  chooser (the headless example needed 401).
- **A second `SecurityFilterChain`** — the catch-all now backs off on its own bean *name*
  (`uniAuthSecurityFilterChain`), not on the type, so adding a chain no longer costs you every
  mechanism. The local OAuth provider needed this.
- A **`UniAuthBasicEntryPoint`** bean — the three-way Basic decision (challenge a program,
  redirect a navigating browser, answer a browser's XHR with a bare 401), published so a
  *second chain* can reuse it instead of reproducing it (#14). Consumers reached for a bare
  `BasicAuthenticationEntryPoint` and the native dialog came back on every expired-session
  XHR, for exactly the paths an API-first front end calls — while both chains were installed,
  both correct, and every test on both sides passed.

- A **`UniAuthHttpSecurityCustomizer`** bean — the chain itself (CSRF, headers, CORS, session
  management), applied **last**, after everything the starter configures, so an application's
  setting wins (#12). This is the only reach into `HttpSecurity`. The starter configures **no
  CSRF**, so Spring Security's session-backed default applies — which is right for the pages
  this library serves and wrong for a front end posting JSON, a machine caller on Basic, or a
  static page's sign-out button, none of which hold a token. The failure is a silent 403 on
  writes only, so every GET keeps working and nothing logs. Two traps, both in `csrf.adoc`:
  calling `authorizeHttpRequests` here adds rules *after* the catch-all where the first match
  already won, and a blanket `csrf(...disable)` unprotects the login form, `POST /logout` and
  the invitation acceptance. The single-page recipe needs **both** token handlers — the masking
  one renders the form, the plain one reads the header — because the default
  `XorCsrfTokenRequestAttributeHandler` masks what it renders, so a front end echoing the raw
  cookie back is refused with the same 403 it was trying to fix.

- An **`InvitationStore`** bean — the invitation table, like `ApprovalStore` is the approval
  one. Unlike it, this SPI can enumerate from the start (#10 is a real gap, but a sibling
  does not inherit it). An **`InvitationRedeemedEvent`** listener is how an application links
  the admitted login to its own record; it may refuse by throwing, which leaves the principal
  pending.

Because that bean *is* an `AuthenticationEntryPoint`, the chain filters it out when looking
for the application's own — taking it would replace the chooser redirect for every browser
navigation. Publishing any bean whose type an `ObjectProvider` already scans needs that check.

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

- **Branching** — one long-lived branch per maintained Boot minor (`3.5`, `4.0`, …); `main`
  tracks the current Boot release (4.1 today). When Boot ships a new minor, `main` rolls forward
  and the outgoing line is cut to its own branch.
- **Versioning** — the project version tracks the Boot version it builds against
  (`4.1.1.1-SNAPSHOT` → Boot 4.1.1), 4th segment being this library's own patch counter. The global
  numeric-only release rule does not apply here.
- **Publishing** — Maven Central via `-Prelease` (GPG signing + sources/javadoc), driven by
  `.github/workflows/maven_release.yml` (`workflow_dispatch` with branch + release + next versions). Never
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
