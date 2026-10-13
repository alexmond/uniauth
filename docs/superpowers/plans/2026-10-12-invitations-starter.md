# Invitations (starter) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an administrator hand a named person a one-use URL that admits them to the record the application already holds for them, on whichever provider they sign in with.

**Architecture:** A token in a URL is the credential. `InvitationController` validates it and stashes it in the session; the ordinary OAuth/form round trip follows; `ApprovalAuthorizationManager` — the one place every request passes exactly once — redeems the stashed token, publishes a linking event, and writes an `APPROVED` approval record. State lives behind a new `InvitationStore` SPI, a sibling of `ApprovalStore`, so the library never owns a table.

**Tech Stack:** Java 21, Spring Boot 4.1.1, Spring Security 7.0.x, Thymeleaf, JUnit 5 + AssertJ + MockMvc, spring-javaformat (tabs).

**Spec:** `docs/superpowers/specs/2026-10-12-invitations-design.md`

This plan covers **phase 1 only** — the starter. Phases 2 (example webapp) and 3 (admin console) get their own plans, and each ships without the next.

## Global Constraints

- **Every `./mvnw` call needs `export JAVA_HOME=$HOME/.jdks/temurin-21` first.** There is no `mvn` on PATH and shell state does not persist between tool calls.
- **Run `./mvnw spring-javaformat:apply` before every build.** `spring-javaformat:validate` fails at `validate`, so an unformatted new file blocks the whole test run — including tests that have nothing to do with it. Tabs, Spring conventions; never hand-format.
- **Never put `@Bean`, `@Order` or any annotation at the start of a line inside a `<pre>{@code ...}</pre>` javadoc block.** The formatter parses it as a real annotation and destroys the block. Mention such annotations inline as `{@code Order}` in prose instead.
- **Checkstyle (+ Spring checks), PMD and JaCoCo ≥ 80% BUNDLE line coverage all fail the build.** Lint rules that bite: **SpringLambda** wants parenthesized single lambda params (`(form) -> …`); **SpringTernary** wants `(a != b) ? x : y`; **AnnotationUseStyle** forbids a trailing comma in annotation arrays; **RedundantFieldInitializer** rejects `= false` on a boolean.
- **Tests are named `*Test`,** not `*Tests` — `SpringTestFileName` is suppressed for exactly this reason.
- **Never let the starter's `@Controller` classes be component-scanned.** They are registered as `@Bean`s by the auto-configuration, so `uniauth.enabled=false` genuinely backs off. The test app lives at `org.alexmond.uniauth.testapp`, outside the starter's package, to keep its scan away from them.
- **Never add an `application.yaml` to a test's `src/test/resources`.** `classpath:/application.yaml` resolves to the *first* match and `target/test-classes` precedes `target/classes`, so it replaces the application's configuration outright. Test overrides go in `application-test.yaml` with `@ActiveProfiles("test")`, or in `@TestPropertySource`.
- **Nothing general may name a SAML or OAuth2 type.** OpenSAML is not on Maven Central; a signature or `instanceof` against those types in a general code path forces the Shibboleth repository into every consumer's build. Nothing in this plan needs them — the whole point of the token is that it works the same for all four mechanisms.
- **New public API ⇒ javadoc on every public type and method,** matching the density of the `approval` package: say *why*, not *what*.
- **Nothing in this work is enabled by default.** `uniauth.approval.invitations.enabled` is `false`, like every other mechanism here.
- Default expiry is `14d`, the configured path must contain `{token}`, and the token carries at least **128 bits** of `SecureRandom` entropy.

## Review Focus

Five inputs the spec implies but does not pin, each most likely to bite a person using this, with the test that pins it placed in the task that owns the code:

1. **`invitations.path` configured without `{token}`** — must fail loudly at startup, not 404 silently forever. *(Task 3)*
2. **A token that is garbage** — a typo, a scanner probing `/invite/../../etc/passwd`, a 10 KB string. Must render as `?invite=unknown`, never a 500 or a path escape. *(Task 6)*
3. **`create` called with a null `ttl` or a null/blank-bearing `roles` list** — an SPI implementor will do this. A null `ttl` means `default-expiry`; a non-positive one is rejected; roles are never allowed to produce `ROLE_null`. *(Task 2)*
4. **Two concurrent requests from the same principal with the same stashed token** — a double-click. Both must succeed as no-ops, leaving exactly one approval. The one-use contract is per *principal*, not per request, and this is the test that proves it. *(Task 4)*
5. **The application runs under a servlet context path** — every redirect in the controller and the gate must carry `request.getContextPath()` or the person lands outside the application. *(Task 7)*

---

## File Structure

New, all under `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/`:

| File | Responsibility |
|---|---|
| `invitation/InvitationToken.java` | The bearer credential. Generation, parsing, equality. Nothing else. |
| `invitation/InvitationStatus.java` | `OPEN · USED · EXPIRED · REVOKED`. |
| `invitation/Invitation.java` | One invitation's facts, and `status(Instant)` derived from them. |
| `invitation/InvitationStore.java` | The SPI. The library owns the flow, never the table. |
| `invitation/InMemoryInvitationStore.java` | The default. Works out of the box, not production-fit. |
| `invitation/InvitationRedeemedEvent.java` | The linking contract: who claimed which `subjectRef`. |
| `invitation/InvitationRedemption.java` | Redeem → publish → approve, in that order. The only writer. |
| `invitation/Invitations.java` | The session attribute name and the stash/read/clear helpers. |
| `web/UniAuthInvitationController.java` | The endpoint: validate, stash, or confirm. |
| `autoconfigure/InvitationConfiguration.java` | Wires the above, and only when asked. |

Modified:

| File | Change |
|---|---|
| `config/UniAuthProperties.java` | `Approval.Invitations` nested class. |
| `approval/ApprovalAuthorizationManager.java` | A second constructor taking the redemption collaborator; redeem before deciding; `invite-only`. |
| `autoconfigure/ApprovalConfiguration.java` | Pass the collaborator through when present. |
| `autoconfigure/UniAuthAutoConfiguration.java` | Permit the invitation path. |
| `web/UniAuthLoginController.java` | The `invite` request parameter. |
| `resources/templates/uniauth/login.html` | One line rendering the `?invite=` reason. |
| `resources/templates/uniauth/invite.html` | New: the confirmation page. |

**Why a new `invitation` package rather than growing `approval`.** The two are siblings, not a hierarchy: `InvitationStore` deliberately does not inherit `ApprovalStore`'s inability to enumerate (#10). Keeping them apart also keeps `ApprovalRecord` closed — widening it with a `subjectRef` would break every `ApprovalStore` implementor, which #5 already did once.

**Three places the spec is underspecified, resolved here.** Each is noted again on the task that implements it:

1. **The approver string.** The spec writes `"invitation:" + id`, but `Invitation` has no `id` — only the token, which is a bearer credential that must not be written into an audit record. Resolved as **`"invitation:" + subjectRef`**, which is also what an auditor actually wants to read.
2. **The order of `decide` and the event.** The spec lists `decide(APPROVED)` at step 2 and the event at step 3, but also says a throwing listener must leave the principal unadmitted. Those contradict: approving first leaves them admitted-but-unlinked, the exact state the spec calls worse than "try again". Resolved by **publishing before deciding** — on a throw the record stays `PENDING`, the invitation stays claimed by this key, and the next request retries.
3. **Which statuses may redeem.** The spec says "an authenticated request whose status is `UNKNOWN`", but its own restart-recovery case describes someone who is already `PENDING`, and the confirmation page implies an already-signed-in principal can claim. Resolved as **redeem whenever the session holds an OPEN token**, whatever the current status. Simpler, and it is the only reading under which all three cases the spec describes actually work.

`Invitation.status(Instant)` is **public**, not package-private as the spec's sketch shows: phases 2 and 3 live in other modules and cannot call it otherwise.

---

### Task 1: The value types

**Files:**
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/InvitationToken.java`
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/InvitationStatus.java`
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/Invitation.java`
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/invitation/InvitationTest.java`

**Interfaces:**
- Consumes: nothing.
- Produces: `InvitationToken.generate() -> InvitationToken`, `InvitationToken.of(String) -> InvitationToken`, `token.value() -> String`; `InvitationStatus.{OPEN,USED,EXPIRED,REVOKED}`; `new Invitation(InvitationToken token, String subjectRef, List<String> roles, Instant createdAt, String createdBy, Instant expiresAt, Instant usedAt, ApprovalKey usedBy, Instant revokedAt)` and `invitation.status(Instant now) -> InvitationStatus`.

- [ ] **Step 1: Write the failing test**

Create `InvitationTest.java`:

```java
package org.alexmond.uniauth.invitation;

import java.time.Instant;
import java.util.List;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The value types. Status is derived rather than stored, because a stored status goes
 * stale the moment an invitation expires with nobody looking at it.
 */
class InvitationTest {

	private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

	private static final ApprovalKey JANE = new ApprovalKey("google", "1234567890");

	@Test
	void aFreshInvitationIsOpen() {
		assertThat(invitation(null, null, null).status(NOW)).isEqualTo(InvitationStatus.OPEN);
	}

	@Test
	void anInvitationPastItsExpiryIsExpired() {
		Invitation past = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100), "admin",
				NOW.minusSeconds(1), null, null, null);

		assertThat(past.status(NOW)).isEqualTo(InvitationStatus.EXPIRED);
	}

	@Test
	void expiryIsExclusiveSoAnInvitationIsStillOpenAtTheInstantItExpires() {
		// A boundary worth pinning rather than discovering: the person clicking at the
		// last second gets in.
		Invitation edge = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100), "admin",
				NOW, null, null, null);

		assertThat(edge.status(NOW)).isEqualTo(InvitationStatus.OPEN);
	}

	@Test
	void aClaimedInvitationIsUsed() {
		assertThat(invitation(NOW.minusSeconds(10), JANE, null).status(NOW)).isEqualTo(InvitationStatus.USED);
	}

	@Test
	void aRevokedInvitationIsRevoked() {
		assertThat(invitation(null, null, NOW.minusSeconds(10)).status(NOW)).isEqualTo(InvitationStatus.REVOKED);
	}

	@Test
	void revocationBeatsExpiryAndUse() {
		// Three could apply at once. Revoked wins, because it is the only one a person
		// decided deliberately and the only one they will look for afterwards.
		Invitation everything = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100),
				"admin", NOW.minusSeconds(50), NOW.minusSeconds(60), JANE, NOW.minusSeconds(40));

		assertThat(everything.status(NOW)).isEqualTo(InvitationStatus.REVOKED);
	}

	@Test
	void useBeatsExpiry() {
		// Claimed on Tuesday, expired on Wednesday: it was used, and saying "expired"
		// would hide that somebody is now holding the record.
		Invitation claimedThenExpired = new Invitation(InvitationToken.generate(), "jane", List.of(),
				NOW.minusSeconds(100), "admin", NOW.minusSeconds(50), NOW.minusSeconds(60), JANE, null);

		assertThat(claimedThenExpired.status(NOW)).isEqualTo(InvitationStatus.USED);
	}

	@Test
	void anInvitationWithNoExpiryNeverExpires() {
		Invitation forever = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100),
				"admin", null, null, null, null);

		assertThat(forever.status(NOW.plusSeconds(99999999L))).isEqualTo(InvitationStatus.OPEN);
	}

	@Test
	void rolesAreCopiedAndNeverNull() {
		Invitation nullRoles = new Invitation(InvitationToken.generate(), "jane", null, NOW, "admin", null, null, null,
				null);

		assertThat(nullRoles.roles()).isEmpty();
	}

	@Test
	void aTokenIsUrlSafeAndCarriesAtLeast128Bits() {
		String value = InvitationToken.generate().value();

		// Base64url of 16 bytes is 22 characters; anything shorter is not 128 bits.
		assertThat(value).hasSizeGreaterThanOrEqualTo(22).matches("[A-Za-z0-9_-]+");
	}

	@Test
	void twoGeneratedTokensDiffer() {
		assertThat(InvitationToken.generate()).isNotEqualTo(InvitationToken.generate());
	}

	@Test
	void tokensWithTheSameValueAreEqualSoTheyWorkAsMapKeys() {
		InvitationToken token = InvitationToken.generate();

		assertThat(InvitationToken.of(token.value())).isEqualTo(token).hasSameHashCodeAs(token);
	}

	@Test
	void aBlankTokenIsRejected() {
		assertThatIllegalArgumentException().isThrownBy(() -> InvitationToken.of("  "));
	}

	@Test
	void aTokenDoesNotPrintItsOwnValue() {
		// It is a bearer credential, and the one place it reliably leaks is a log line
		// that interpolated an object.
		InvitationToken token = InvitationToken.generate();

		assertThat(token.toString()).doesNotContain(token.value());
	}

	private static Invitation invitation(Instant usedAt, ApprovalKey usedBy, Instant revokedAt) {
		return new Invitation(InvitationToken.generate(), "jane", List.of("USER"), NOW.minusSeconds(100), "admin",
				NOW.plusSeconds(100), usedAt, usedBy, revokedAt);
	}

}
```

- [ ] **Step 2: Run the test and watch it fail**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InvitationTest
```

Expected: compilation failure — `package org.alexmond.uniauth.invitation does not exist`.

- [ ] **Step 3: Write `InvitationStatus`**

```java
package org.alexmond.uniauth.invitation;

/**
 * Where an invitation stands, derived from its own timestamps rather than stored.
 *
 * <p>
 * Stored status would go stale the moment an invitation expired with nobody looking at
 * it, and the store would then need a sweeper to stay honest.
 */
public enum InvitationStatus {

	/** Not yet claimed, not expired, not revoked. The only status that may be redeemed. */
	OPEN,

	/** Claimed. One principal holds it, permanently — see {@code Invitation.usedBy}. */
	USED,

	/** Past its expiry, unclaimed. Re-inviting creates a new invitation, never reopens this one. */
	EXPIRED,

	/** Withdrawn by a person. Beats every other status, because it is the only deliberate one. */
	REVOKED

}
```

- [ ] **Step 4: Write `InvitationToken`**

```java
package org.alexmond.uniauth.invitation;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.util.Assert;

/**
 * The invitation's credential: whoever holds it can claim the record it names.
 *
 * <p>
 * Opaque, URL-safe, and generated from {@link SecureRandom} with 128 bits of entropy. It
 * is never derived from the {@code subjectRef} — a token a person could guess from
 * somebody's name would not be a credential at all.
 *
 * <p>
 * Deliberately not a signed self-contained token. One-use and revocation both require a
 * store lookup, so statelessness would buy nothing, while a signed token would have to
 * ride the provider round trip as OAuth2 {@code state} or SAML {@code RelayState} — two
 * mechanisms, two implementations, which is precisely the split the single chain exists to
 * avoid.
 *
 * @param value the opaque, URL-safe token text
 */
public record InvitationToken(String value) {

	private static final SecureRandom RANDOM = new SecureRandom();

	private static final int ENTROPY_BYTES = 16;

	public InvitationToken {
		Assert.hasText(value, "An invitation token must have text");
	}

	/**
	 * Mints a fresh token.
	 * @return a token with 128 bits of entropy, encoded URL-safely and without padding so
	 * it needs no escaping in a path
	 */
	public static InvitationToken generate() {
		byte[] bytes = new byte[ENTROPY_BYTES];
		RANDOM.nextBytes(bytes);
		return new InvitationToken(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
	}

	/**
	 * Wraps token text that arrived from outside — a URL, or a store.
	 * @param value the token text, which is not validated beyond being non-blank: an
	 * unrecognised token is a lookup miss, not an error
	 * @return the token
	 */
	public static InvitationToken of(String value) {
		return new InvitationToken(value);
	}

	/**
	 * Withholds the value.
	 *
	 * <p>
	 * This is a bearer credential, and the one place such a thing reliably leaks is a log
	 * line that interpolated an object someone assumed was harmless.
	 * @return a constant placeholder
	 */
	@Override
	public String toString() {
		return "InvitationToken[redacted]";
	}

}
```

- [ ] **Step 5: Write `Invitation`**

```java
package org.alexmond.uniauth.invitation;

import java.time.Instant;
import java.util.List;

import org.alexmond.uniauth.approval.ApprovalKey;

/**
 * One invitation: who it names, who may use it, and what became of it.
 *
 * <p>
 * {@code usedBy} is what makes the link durable without anybody listening for the event.
 * It records permanently that a given {@link ApprovalKey} claimed a given
 * {@code subjectRef}, so {@code (google, sub) -> Jane} is recoverable by querying the
 * store. That is why {@code ApprovalRecord} does not gain a {@code subjectRef} field:
 * widening it would be breaking for every {@code ApprovalStore} implementor, which #5
 * already did once.
 *
 * @param token the credential, which is also the store's key
 * @param subjectRef the application's own identifier for the person — a row id, a
 * username, whatever the application already calls Jane. UniAuth never interprets it
 * @param roles what the invited principal is granted on admission, empty to fall back to
 * {@code uniauth.approval.default-roles}
 * @param createdAt when it was minted
 * @param createdBy who minted it, for the audit trail
 * @param expiresAt when it stops working, or {@code null} to never expire
 * @param usedAt when it was claimed, {@code null} while unclaimed
 * @param usedBy which principal claimed it, {@code null} while unclaimed. One-use means
 * one <em>principal</em>: re-claiming with this same key is a no-op, so a transient
 * failure in the application does not strand the invited person with a dead URL
 * @param revokedAt when a person withdrew it, {@code null} otherwise
 */
public record Invitation(InvitationToken token, String subjectRef, List<String> roles, Instant createdAt,
		String createdBy, Instant expiresAt, Instant usedAt, ApprovalKey usedBy, Instant revokedAt) {

	public Invitation {
		roles = (roles != null) ? List.copyOf(roles) : List.of();
	}

	/**
	 * Where this invitation stands, as of a given moment.
	 *
	 * <p>
	 * Precedence matters when more than one applies. Revocation wins, because it is the
	 * only status a person chose deliberately and the only one they will go looking for
	 * afterwards. Use beats expiry, because "expired" would hide that somebody is already
	 * holding the record.
	 * @param now the moment to judge against, passed in rather than read so a test can
	 * assert on boundaries without sleeping
	 * @return the status, never {@code null}
	 */
	public InvitationStatus status(Instant now) {
		if (this.revokedAt != null) {
			return InvitationStatus.REVOKED;
		}
		if (this.usedAt != null) {
			return InvitationStatus.USED;
		}
		// Exclusive, so the person clicking at the last second gets in.
		if (this.expiresAt != null && !now.isBefore(this.expiresAt)) {
			return InvitationStatus.EXPIRED;
		}
		return InvitationStatus.OPEN;
	}

}
```

- [ ] **Step 6: Format, then run the test and watch it pass**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/mvnw -q -f /home/alexm/IdeaProjects/uniauth/pom.xml spring-javaformat:apply
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InvitationTest
```

Expected: PASS, 13 tests.

- [ ] **Step 7: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/invitation
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
feat(invitations): the value types (#29)

Status is derived from the timestamps rather than stored, so an invitation
that expires with nobody looking at it is still honest and the store needs
no sweeper. The token redacts itself: it is a bearer credential, and the one
place such a thing reliably leaks is a log line that interpolated an object.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

### Task 2: `InvitationStore` and the in-memory default

**Files:**
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/InvitationStore.java`
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/InMemoryInvitationStore.java`
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/invitation/InMemoryInvitationStoreTest.java`

**Interfaces:**
- Consumes: `Invitation`, `InvitationToken`, `InvitationStatus` (Task 1); `ApprovalKey` (existing).
- Produces: `InvitationStore` with `create(String subjectRef, Duration ttl, List<String> roles, String createdBy) -> Invitation`, `find(InvitationToken) -> Optional<Invitation>`, `redeem(InvitationToken, ApprovalKey) -> Invitation`, `revoke(InvitationToken, String revokedBy) -> void`, `list(InvitationStatus...) -> List<Invitation>`. `redeem` throws `InvitationNotRedeemableException` (a nested `RuntimeException` on `InvitationStore`) when the invitation is absent, not OPEN, or already claimed by a *different* key. Also `new InMemoryInvitationStore()` and `new InMemoryInvitationStore(Clock, Duration defaultExpiry)`.

**Review Focus item 3 lands here:** null `ttl`, non-positive `ttl`, and null-or-blank-bearing `roles`.

- [ ] **Step 1: Write the failing test**

Create `InMemoryInvitationStoreTest.java`:

```java
package org.alexmond.uniauth.invitation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The store contract, exercised on the in-memory default.
 *
 * <p>
 * {@code redeem} is the only place one-use is enforced, and the only thing an implementor
 * can get wrong silently — a read-then-write passes every single-threaded test and admits
 * two people under load. Hence the concurrency cases.
 */
class InMemoryInvitationStoreTest {

	private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

	private static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	private static final ApprovalKey BOB = new ApprovalKey("google", "bob-sub");

	private InMemoryInvitationStore store;

	@BeforeEach
	void freshStore() {
		this.store = new InMemoryInvitationStore(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(14));
	}

	@Test
	void aCreatedInvitationIsOpenAndFindable() {
		Invitation created = this.store.create("jane", Duration.ofDays(7), List.of("USER"), "admin");

		assertThat(created.status(NOW)).isEqualTo(InvitationStatus.OPEN);
		assertThat(created.subjectRef()).isEqualTo("jane");
		assertThat(created.createdBy()).isEqualTo("admin");
		assertThat(created.expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(7)));
		assertThat(this.store.find(created.token())).contains(created);
	}

	@Test
	void aNullTtlFallsBackToTheConfiguredDefault() {
		// Review Focus 3. An SPI implementor will pass null, and "never expires" is the
		// wrong default for a credential anyone can forward.
		Invitation created = this.store.create("jane", null, List.of(), "admin");

		assertThat(created.expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(14)));
	}

	@Test
	void aNonPositiveTtlIsRejectedRatherThanCreatingSomethingBornExpired() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.store.create("jane", Duration.ZERO, List.of(), "a"));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.store.create("jane", Duration.ofSeconds(-1), List.of(), "a"));
	}

	@Test
	void blankAndNullRolesAreDroppedSoNobodyIsGrantedRoleNull() {
		// Review Focus 3. These reach ApprovalAuthoritiesFilter, which prefixes whatever
		// it is handed — "ROLE_null" would be granted and then never match anything.
		List<String> dirty = new ArrayList<>();
		dirty.add("USER");
		dirty.add(null);
		dirty.add("   ");
		dirty.add(" ADMIN ");

		Invitation created = this.store.create("jane", null, dirty, "admin");

		assertThat(created.roles()).containsExactly("USER", "ADMIN");
	}

	@Test
	void aMissingSubjectRefIsRejected() {
		// The subjectRef is the whole point: an invitation to nobody in particular is a
		// bearer token for an unidentified record.
		assertThatIllegalArgumentException().isThrownBy(() -> this.store.create("  ", null, List.of(), "admin"));
	}

	@Test
	void anUnknownTokenIsAMissRatherThanAnError() {
		assertThat(this.store.find(InvitationToken.generate())).isEmpty();
	}

	@Test
	void redeemingClaimsTheInvitationForThatPrincipal() {
		Invitation created = this.store.create("jane", null, List.of("USER"), "admin");

		Invitation claimed = this.store.redeem(created.token(), JANE);

		assertThat(claimed.usedBy()).isEqualTo(JANE);
		assertThat(claimed.usedAt()).isEqualTo(NOW);
		assertThat(claimed.status(NOW)).isEqualTo(InvitationStatus.USED);
		assertThat(this.store.find(created.token())).contains(claimed);
	}

	@Test
	void reclaimingWithTheSameKeyIsANoOpSoAFailedListenerCanBeRetried() {
		// The property that stops a transient application failure stranding Jane with a
		// URL that can never work again. One-use means one principal, not one request.
		Invitation created = this.store.create("jane", null, List.of("USER"), "admin");
		Invitation first = this.store.redeem(created.token(), JANE);

		Invitation again = this.store.redeem(created.token(), JANE);

		assertThat(again).isEqualTo(first);
		assertThat(again.usedAt()).isEqualTo(first.usedAt());
	}

	@Test
	void aDifferentPrincipalCannotClaimAnInvitationAlreadyTaken() {
		Invitation created = this.store.create("jane", null, List.of("USER"), "admin");
		this.store.redeem(created.token(), JANE);

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), BOB));
	}

	@Test
	void anExpiredInvitationCannotBeRedeemed() {
		InMemoryInvitationStore shortLived = new InMemoryInvitationStore(Clock.fixed(NOW, ZoneOffset.UTC),
				Duration.ofDays(14));
		Invitation created = shortLived.create("jane", Duration.ofSeconds(1), List.of(), "admin");
		InMemoryInvitationStore later = adopt(shortLived, NOW.plusSeconds(60));

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> later.redeem(created.token(), JANE));
	}

	@Test
	void aRevokedInvitationCannotBeRedeemed() {
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		this.store.revoke(created.token(), "admin");

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), JANE));
		assertThat(this.store.find(created.token())).get()
			.satisfies((invitation) -> assertThat(invitation.status(NOW)).isEqualTo(InvitationStatus.REVOKED));
	}

	@Test
	void anUnknownTokenCannotBeRedeemed() {
		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(InvitationToken.generate(), JANE));
	}

	@Test
	void revokingAnUnknownTokenIsNotAnError() {
		// Same reason DirectoryUserStore looks an entry up before unbinding: a caller
		// tidying up should not have to know whether there is anything to tidy.
		this.store.revoke(InvitationToken.generate(), "admin");
	}

	@Test
	void revokingAClaimedInvitationDoesNotUnclaimIt() {
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		this.store.revoke(created.token(), "admin");

		// Still USED, because somebody is holding the record and the audit trail has to
		// keep saying who.
		assertThat(this.store.find(created.token())).get()
			.satisfies((invitation) -> assertThat(invitation.usedBy()).isEqualTo(JANE));
	}

	@Test
	void listWithNoArgumentsReturnsEverything() {
		this.store.create("jane", null, List.of(), "admin");
		this.store.create("bob", null, List.of(), "admin");

		assertThat(this.store.list()).hasSize(2);
	}

	@Test
	void listFiltersByStatusWhichIsWhyThisSpiDoesNotInheritApprovalStoreSLimitation() {
		Invitation open = this.store.create("jane", null, List.of(), "admin");
		Invitation used = this.store.create("bob", null, List.of(), "admin");
		this.store.redeem(used.token(), BOB);
		Invitation revoked = this.store.create("carol", null, List.of(), "admin");
		this.store.revoke(revoked.token(), "admin");

		assertThat(this.store.list(InvitationStatus.OPEN)).extracting(Invitation::token).containsExactly(open.token());
		assertThat(this.store.list(InvitationStatus.USED, InvitationStatus.REVOKED)).extracting(Invitation::subjectRef)
			.containsExactlyInAnyOrder("bob", "carol");
	}

	@Test
	void listIsNewestFirstSoTheInvitationJustCreatedIsAtTheTop() {
		AtomicInteger tick = new AtomicInteger();
		InMemoryInvitationStore ticking = new InMemoryInvitationStore(new Clock() {
			@Override
			public ZoneOffset getZone() {
				return ZoneOffset.UTC;
			}

			@Override
			public Clock withZone(java.time.ZoneId zone) {
				return this;
			}

			@Override
			public Instant instant() {
				return NOW.plusSeconds(tick.getAndIncrement());
			}
		}, Duration.ofDays(14));
		ticking.create("first", null, List.of(), "admin");
		ticking.create("second", null, List.of(), "admin");

		assertThat(ticking.list()).extracting(Invitation::subjectRef).containsExactly("second", "first");
	}

	@Test
	void reInvitingCreatesANewInvitationRatherThanReopeningTheDeadOne() {
		Invitation first = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(first.token(), JANE);

		Invitation second = this.store.create("jane", null, List.of(), "admin");

		assertThat(second.token()).isNotEqualTo(first.token());
		assertThat(this.store.find(first.token())).get()
			.satisfies((invitation) -> assertThat(invitation.status(NOW)).isEqualTo(InvitationStatus.USED));
	}

	@Test
	void onlyOneOfManySimultaneousPrincipalsClaimsTheInvitation() throws Exception {
		// The case a read-then-write implementation passes every other test and fails:
		// two logins landing at once must not both claim Jane.
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		int racers = 16;
		CountDownLatch startLine = new CountDownLatch(1);
		AtomicInteger claimed = new AtomicInteger();
		ConcurrentHashMap<ApprovalKey, Boolean> winners = new ConcurrentHashMap<>();
		ExecutorService pool = Executors.newFixedThreadPool(racers);
		try {
			for (int i = 0; i < racers; i++) {
				ApprovalKey key = new ApprovalKey("google", "racer-" + i);
				pool.submit(() -> {
					try {
						startLine.await();
						this.store.redeem(created.token(), key);
						claimed.incrementAndGet();
						winners.put(key, Boolean.TRUE);
					}
					catch (InvitationStore.InvitationNotRedeemableException | InterruptedException expected) {
						// Everybody but one loses, which is the point.
					}
				});
			}
			startLine.countDown();
			pool.shutdown();
			assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
		}
		finally {
			pool.shutdownNow();
		}

		assertThat(claimed.get()).isOne();
		assertThat(this.store.find(created.token())).get()
			.satisfies((invitation) -> assertThat(winners).containsKey(invitation.usedBy()));
	}

	@Test
	void manySimultaneousRequestsFromTheSamePrincipalAllSucceed() throws Exception {
		// Review Focus 4, the double-click. Every one of these is the same person, so
		// every one must succeed as a no-op — refusing the second would turn a stray
		// second request into a permanent lockout.
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		int attempts = 16;
		CountDownLatch startLine = new CountDownLatch(1);
		AtomicInteger succeeded = new AtomicInteger();
		ExecutorService pool = Executors.newFixedThreadPool(attempts);
		try {
			for (int i = 0; i < attempts; i++) {
				pool.submit(() -> {
					try {
						startLine.await();
						this.store.redeem(created.token(), JANE);
						succeeded.incrementAndGet();
					}
					catch (RuntimeException | InterruptedException unexpected) {
						// Left to the assertion below rather than failing on this thread.
					}
				});
			}
			startLine.countDown();
			pool.shutdown();
			assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
		}
		finally {
			pool.shutdownNow();
		}

		assertThat(succeeded.get()).isEqualTo(attempts);
	}

	/** Copies a store's contents into one reading a later clock. */
	private static InMemoryInvitationStore adopt(InMemoryInvitationStore source, Instant later) {
		InMemoryInvitationStore adopted = new InMemoryInvitationStore(Clock.fixed(later, ZoneOffset.UTC),
				Duration.ofDays(14));
		source.list().forEach(adopted::put);
		return adopted;
	}

}
```

- [ ] **Step 2: Run the test and watch it fail**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InMemoryInvitationStoreTest
```

Expected: compilation failure — `cannot find symbol: class InvitationStore`.

- [ ] **Step 3: Write `InvitationStore`**

```java
package org.alexmond.uniauth.invitation;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.alexmond.uniauth.approval.ApprovalKey;

/**
 * Where invitations live.
 *
 * <p>
 * An SPI, on the same bargain as {@code ApprovalStore}: UniAuth owns the flow and never
 * the table. Owning one would force Spring Data, a schema and a migration story onto every
 * application that only wanted a login page.
 *
 * <p>
 * Unlike {@code ApprovalStore}, this interface can enumerate from the start. That gap in
 * the approval SPI is real (#10), but a sibling does not inherit it — an administrator
 * cannot manage invitations they cannot list.
 *
 * <p>
 * Implementations must be safe for concurrent use.
 */
public interface InvitationStore {

	/**
	 * Mints an invitation for a person the application already holds a record for.
	 * @param subjectRef the application's own identifier for that person. UniAuth never
	 * interprets it; it is handed back on redemption so the application can do the linking
	 * @param ttl how long it stays usable, or {@code null} for the configured
	 * {@code default-expiry}. Must be positive if given
	 * @param roles granted on admission, or empty to fall back to
	 * {@code uniauth.approval.default-roles}. Null and blank entries are dropped, because
	 * they would otherwise reach the authorities filter and be granted as {@code ROLE_null}
	 * @param createdBy who is inviting, for the audit trail
	 * @return the new invitation, including its token
	 * @throws IllegalArgumentException if {@code subjectRef} is blank or {@code ttl} is
	 * not positive
	 */
	Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy);

	/**
	 * Looks an invitation up.
	 * @param token the token presented
	 * @return the invitation, or empty when nothing matches. An unrecognised token is a
	 * miss rather than an error: most of them are typos and scanners
	 */
	Optional<Invitation> find(InvitationToken token);

	/**
	 * Atomically claims an OPEN invitation for this principal.
	 *
	 * <p>
	 * <strong>This is the only place one-use is enforced, and it must be a compare-and-set
	 * rather than a read-then-write.</strong> A read-then-write passes every
	 * single-threaded test and admits two people under load; two simultaneous logins must
	 * not both claim Jane.
	 *
	 * <p>
	 * One-use means one <em>principal</em>, not one request. Claiming again with the
	 * <em>same</em> key succeeds and is a no-op — which is what lets a transient failure
	 * in the application be retried, rather than stranding the invited person with a URL
	 * that can never work again. Claiming with a different key fails.
	 * @param token the token presented
	 * @param admitted the principal claiming it
	 * @return the claimed invitation, carrying {@code usedBy} and {@code usedAt}
	 * @throws InvitationNotRedeemableException if there is no such invitation, or it is
	 * expired or revoked, or another principal already claimed it
	 */
	Invitation redeem(InvitationToken token, ApprovalKey admitted);

	/**
	 * Withdraws an invitation.
	 *
	 * <p>
	 * Revoking one already claimed does not unclaim it: somebody is holding the record,
	 * and the audit trail has to keep saying who.
	 * @param token the token to withdraw; withdrawing an unknown one is not an error
	 * @param revokedBy who withdrew it, for the audit trail
	 */
	void revoke(InvitationToken token, String revokedBy);

	/**
	 * Every invitation in the given states, newest first.
	 * @param statuses the states wanted, or none at all for every invitation
	 * @return the matching invitations, newest first so the one just created is at the top
	 */
	List<Invitation> list(InvitationStatus... statuses);

	/**
	 * Thrown when an invitation cannot be claimed.
	 *
	 * <p>
	 * Deliberately one exception rather than four. The caller's reaction is identical in
	 * every case — fall through to the ordinary approval gate — and distinguishing them
	 * would tell whoever presented the token more about the store than they need.
	 */
	class InvitationNotRedeemableException extends RuntimeException {

		/**
		 * @param message why it could not be claimed, for the log and not for the caller
		 */
		public InvitationNotRedeemableException(String message) {
			super(message);
		}

	}

}
```

- [ ] **Step 4: Write `InMemoryInvitationStore`**

```java
package org.alexmond.uniauth.invitation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.alexmond.uniauth.approval.ApprovalKey;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * The default {@link InvitationStore}: a map, and nothing else.
 *
 * <p>
 * Supplied so the flow works out of the box and in tests, and <strong>not
 * production-fit</strong>, for the same two reasons {@code InMemoryApprovalStore} is not:
 * invitations are lost on restart, and nothing is shared between instances, so behind a
 * load balancer an invitation exists only on the node that minted it. A console pointed
 * at an in-memory store likewise sees only the invitations created in its own process.
 *
 * <p>
 * Durability is the deployment's choice, so the starter warns about this rather than
 * refusing to start — see {@code InvitationConfiguration}.
 */
public class InMemoryInvitationStore implements InvitationStore {

	private final Map<InvitationToken, Invitation> invitations = new ConcurrentHashMap<>();

	private final Clock clock;

	private final Duration defaultExpiry;

	/** Uses the system UTC clock and a fourteen-day default expiry. */
	public InMemoryInvitationStore() {
		this(Clock.systemUTC(), Duration.ofDays(14));
	}

	/**
	 * Creates a store reading time from the given clock.
	 * @param clock source of the created, used and revoked timestamps; injectable so a
	 * test can assert on expiry boundaries without sleeping
	 * @param defaultExpiry used when {@code create} is given no ttl
	 */
	public InMemoryInvitationStore(Clock clock, Duration defaultExpiry) {
		this.clock = clock;
		this.defaultExpiry = defaultExpiry;
	}

	@Override
	public Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy) {
		Assert.hasText(subjectRef, "An invitation must name a subjectRef");
		Assert.isTrue(ttl == null || (!ttl.isZero() && !ttl.isNegative()),
				"An invitation's ttl must be positive, not " + ttl);
		Instant now = this.clock.instant();
		Duration effective = (ttl != null) ? ttl : this.defaultExpiry;
		Invitation invitation = new Invitation(InvitationToken.generate(), subjectRef.trim(), clean(roles), now,
				createdBy, (effective != null) ? now.plus(effective) : null, null, null, null);
		this.invitations.put(invitation.token(), invitation);
		return invitation;
	}

	@Override
	public Optional<Invitation> find(InvitationToken token) {
		return Optional.ofNullable(this.invitations.get(token));
	}

	@Override
	public Invitation redeem(InvitationToken token, ApprovalKey admitted) {
		Instant now = this.clock.instant();
		// compute, not get-then-put: the claim has to be a compare-and-set or two
		// simultaneous logins both take Jane.
		Invitation claimed = this.invitations.compute(token, (unused, existing) -> {
			if (existing == null) {
				return null;
			}
			if (admitted.equals(existing.usedBy())) {
				// Same principal claiming again. A no-op, so a failed listener can be
				// retried instead of stranding the invited person.
				return existing;
			}
			if (existing.status(now) != InvitationStatus.OPEN) {
				return existing;
			}
			return new Invitation(existing.token(), existing.subjectRef(), existing.roles(), existing.createdAt(),
					existing.createdBy(), existing.expiresAt(), now, admitted, existing.revokedAt());
		});
		if (claimed == null || !admitted.equals(claimed.usedBy())) {
			throw new InvitationNotRedeemableException("The invitation is not open to this principal");
		}
		return claimed;
	}

	@Override
	public void revoke(InvitationToken token, String revokedBy) {
		Instant now = this.clock.instant();
		this.invitations.computeIfPresent(token,
				(unused, existing) -> (existing.revokedAt() != null) ? existing
						: new Invitation(existing.token(), existing.subjectRef(), existing.roles(),
								existing.createdAt(), existing.createdBy(), existing.expiresAt(), existing.usedAt(),
								existing.usedBy(), now));
	}

	@Override
	public List<Invitation> list(InvitationStatus... statuses) {
		Instant now = this.clock.instant();
		Set<InvitationStatus> wanted = (statuses.length > 0) ? Set.copyOf(Arrays.asList(statuses))
				: Set.of(InvitationStatus.values());
		return this.invitations.values()
			.stream()
			.filter((invitation) -> wanted.contains(invitation.status(now)))
			.sorted(Comparator.comparing(Invitation::createdAt).reversed())
			.toList();
	}

	/**
	 * Adopts an invitation minted elsewhere. Exists for tests that need a store reading a
	 * different clock over the same contents.
	 * @param invitation the invitation to take in
	 */
	void put(Invitation invitation) {
		this.invitations.put(invitation.token(), invitation);
	}

	/**
	 * Drops null and blank roles and trims the rest.
	 *
	 * <p>
	 * They would otherwise reach {@code ApprovalAuthoritiesFilter}, which prefixes
	 * whatever it is handed: {@code ROLE_null} would be granted and then match nothing,
	 * which reads as a broken application rather than a bad invitation.
	 */
	private static List<String> clean(List<String> roles) {
		if (roles == null) {
			return List.of();
		}
		return roles.stream().filter(StringUtils::hasText).map(String::trim).distinct().toList();
	}

}
```

- [ ] **Step 5: Format, then run the test and watch it pass**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/mvnw -q -f /home/alexm/IdeaProjects/uniauth/pom.xml spring-javaformat:apply
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InMemoryInvitationStoreTest
```

Expected: PASS, 19 tests. If `onlyOneOfManySimultaneousPrincipalsClaimsTheInvitation` fails, the claim is not atomic — fix `redeem`, do not loosen the test.

- [ ] **Step 6: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/invitation
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
feat(invitations): the store SPI and its in-memory default (#29)

redeem is a compare-and-set, not a read-then-write: the latter passes every
single-threaded test and admits two people under load. Claiming again with
the same key is a no-op, so one-use means one principal rather than one
request — a transient failure in the application retries instead of
stranding the invited person with a dead URL.

list exists from the start. The approval SPI's inability to enumerate
anything but pending() is a real gap (#10), but a sibling does not inherit
it: an administrator cannot manage invitations they cannot see.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

### Task 3: Configuration properties

**Files:**
- Modify: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/config/UniAuthProperties.java` — add `Invitations` inside the existing `Approval` nested class
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/config/UniAuthInvitationPropertiesTest.java`

**Interfaces:**
- Consumes: nothing.
- Produces: `properties.getApproval().getInvitations()` returning `UniAuthProperties.Approval.Invitations` with Lombok accessors `isEnabled()`, `getPath()`, `getDefaultExpiry()`, `isInviteOnly()`, plus `validate()` and `tokenPatternOrThrow()`.

**Review Focus item 1 lands here:** `path` without `{token}`.

- [ ] **Step 1: Write the failing test**

Create `UniAuthInvitationPropertiesTest.java`:

```java
package org.alexmond.uniauth.config;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * The invitation properties, and the one of them that can be set to something that never
 * works.
 */
class UniAuthInvitationPropertiesTest {

	@Test
	void invitationsAreOffByDefaultLikeEveryOtherMechanismHere() {
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties().getApproval().getInvitations();

		assertThat(invitations.isEnabled()).isFalse();
		assertThat(invitations.isInviteOnly()).isFalse();
		assertThat(invitations.getPath()).isEqualTo("/invite/{token}");
		assertThat(invitations.getDefaultExpiry()).isEqualTo(Duration.ofDays(14));
	}

	@Test
	void aPathWithoutTheTokenPlaceholderIsRejectedAtStartup() {
		// Review Focus 1. Without this the controller maps a literal path, every
		// invitation 404s, and nothing anywhere says why.
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties.Approval.Invitations();
		invitations.setPath("/invite");

		assertThatIllegalStateException().isThrownBy(invitations::validate)
			.withMessageContaining("{token}")
			.withMessageContaining("/invite");
	}

	@Test
	void aPathNotStartingWithASlashIsRejectedAtStartup() {
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties.Approval.Invitations();
		invitations.setPath("invite/{token}");

		assertThatIllegalStateException().isThrownBy(invitations::validate);
	}

	@Test
	void aCustomPathIsAccepted() {
		UniAuthProperties.Approval.Invitations invitations = new UniAuthProperties.Approval.Invitations();
		invitations.setPath("/welcome/{token}");

		invitations.validate();

		assertThat(invitations.getPath()).isEqualTo("/welcome/{token}");
	}

	@Test
	void theDurationBindsInBootSShorthand() {
		// "14d" rather than "PT336H", because nobody writes an invitation expiry in ISO
		// 8601.
		UniAuthProperties bound = new Binder(new MapConfigurationPropertySource(
				java.util.Map.of("uniauth.approval.invitations.enabled", "true",
						"uniauth.approval.invitations.default-expiry", "3d",
						"uniauth.approval.invitations.invite-only", "true")))
			.bind("uniauth", UniAuthProperties.class)
			.orElseThrow();

		assertThat(bound.getApproval().getInvitations().getDefaultExpiry()).isEqualTo(Duration.ofDays(3));
		assertThat(bound.getApproval().getInvitations().isInviteOnly()).isTrue();
	}

}
```

- [ ] **Step 2: Run the test and watch it fail**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh UniAuthInvitationPropertiesTest
```

Expected: compilation failure — `cannot find symbol: method getInvitations()`.

- [ ] **Step 3: Add the nested class**

Inside the existing `public static class Approval` in `UniAuthProperties.java`, after the `defaultRoles` field, add:

```java
		private Invitations invitations = new Invitations();

		/**
		 * Admitting a named person before their first login.
		 *
		 * <p>
		 * The approval gate answers "somebody logged in; do we let them in?", which needs
		 * a stranger to arrive first. Invitations are the other order: the application
		 * already holds a record for Jane, and hands her a one-use URL that attaches
		 * whichever login she completes to <em>that record</em>. Account claiming, not
		 * user provisioning.
		 */
		@Data
		public static class Invitations {

			private boolean enabled;

			/**
			 * Where an invitation is redeemed. Must contain {@code {token}}, and the
			 * starter permits this path on its chain — it has to work before anybody has
			 * logged in.
			 */
			private String path = "/invite/{token}";

			/** How long an invitation lasts when the creator names no ttl. */
			private Duration defaultExpiry = Duration.ofDays(14);

			/**
			 * Refuse anyone who was not invited, rather than holding them for approval.
			 *
			 * <p>
			 * An uninvited principal is recorded {@code DENIED} and gets a plain 403
			 * instead of the waiting page. Telling somebody who will never be admitted to
			 * keep waiting is a lie, and the waiting page implies a queue that nobody is
			 * reading.
			 */
			private boolean inviteOnly;

			/**
			 * Fails fast on a path that could never work.
			 *
			 * <p>
			 * A path with no {@code {token}} maps a literal URL: every invitation 404s,
			 * and nothing anywhere says why. Checked at startup rather than left to
			 * surface as a mystery one link at a time — the same reason
			 * {@code ManagedApplication.validate()} exists in the console.
			 * @throws IllegalStateException if the path is unusable
			 */
			public void validate() {
				if (this.path == null || !this.path.startsWith("/") || !this.path.contains("{token}")) {
					throw new IllegalStateException(
							"uniauth.approval.invitations.path must start with '/' and contain '{token}', but was '"
									+ this.path + "'");
				}
			}

		}
```

Add `import java.time.Duration;` to the file's imports.

- [ ] **Step 4: Format, then run the test and watch it pass**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/mvnw -q -f /home/alexm/IdeaProjects/uniauth/pom.xml spring-javaformat:apply
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh UniAuthInvitationPropertiesTest
```

Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/config/UniAuthProperties.java uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/config
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
feat(invitations): configuration properties (#29)

The path is validated at startup rather than left to surface one dead link
at a time: without {token} the controller maps a literal URL, every
invitation 404s, and nothing says why. Same reason the console's
ManagedApplication.validate() exists.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

### Task 4: The event and the redemption collaborator

**Files:**
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/InvitationRedeemedEvent.java`
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/Invitations.java`
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation/InvitationRedemption.java`
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/invitation/InvitationRedemptionTest.java`

**Interfaces:**
- Consumes: `InvitationStore`, `Invitation`, `InvitationToken` (Task 2); `UniAuthProperties.Approval.Invitations` (Task 3); `ApprovalStore`, `ApprovalKey`, `ApprovalStatus`, `PrincipalIdentity` (existing); `AuthProviderType` (existing).
- Produces:
  - `new InvitationRedeemedEvent(ApprovalKey key, String subjectRef, PrincipalIdentity identity, InvitationToken token)`
  - `Invitations.stash(HttpServletRequest, InvitationToken)`, `Invitations.pending(HttpServletRequest) -> InvitationToken` (null when none), `Invitations.clear(HttpServletRequest)`, `Invitations.SESSION_ATTRIBUTE`
  - `new InvitationRedemption(InvitationStore, ApprovalStore, ApplicationEventPublisher, UniAuthProperties)` with `boolean admit(HttpServletRequest request, ApprovalKey key, PrincipalIdentity identity, AuthProviderType mechanism)` — `true` when the principal is now APPROVED, `false` when there was nothing to redeem **or** a listener refused.

**Review Focus item 4 lands here:** concurrent `admit` from one principal.

**This task implements the two spec resolutions.** The approver string is `"invitation:" + subjectRef`, not the token. The event is published **before** `decide(APPROVED)`, not after.

- [ ] **Step 1: Write the failing test**

Create `InvitationRedemptionTest.java`:

```java
package org.alexmond.uniauth.invitation;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.InMemoryApprovalStore;
import org.alexmond.uniauth.approval.PrincipalIdentity;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Redemption, unit-tested away from the chain.
 *
 * <p>
 * The ordering is the whole point and it is easiest to see here: the event is published
 * <em>before</em> the approval is written, so a listener that throws leaves the principal
 * unadmitted rather than admitted-and-unlinked.
 */
class InvitationRedemptionTest {

	private static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	private static final ApprovalKey BOB = new ApprovalKey("google", "bob-sub");

	private static final PrincipalIdentity IDENTITY = new PrincipalIdentity("Jane Smith", "jane@example.com",
			Boolean.TRUE, "jane-sub");

	private InvitationStore invitations;

	private ApprovalStore approvals;

	private UniAuthProperties properties;

	private List<Object> published;

	@BeforeEach
	void freshCollaborators() {
		this.invitations = new InMemoryInvitationStore(Clock.systemUTC(), Duration.ofDays(14));
		this.approvals = new InMemoryApprovalStore();
		this.properties = new UniAuthProperties();
		this.properties.getApproval().getInvitations().setEnabled(true);
		this.published = new java.util.ArrayList<>();
	}

	@Test
	void anInvitedPrincipalIsApprovedWithTheInvitationAsApprover() {
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		boolean admitted = redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY,
				AuthProviderType.OAUTH2);

		assertThat(admitted).isTrue();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get().satisfies((record) -> {
			// The subjectRef, not the token: the token is a bearer credential and has no
			// business in an audit record, and "invitation:jane" is what an auditor wants
			// to read anyway.
			assertThat(record.decidedBy()).isEqualTo("invitation:jane");
			assertThat(record.roles()).containsExactly("FAMILY");
			assertThat(record.identity()).isEqualTo(IDENTITY);
			assertThat(record.mechanism()).isEqualTo(AuthProviderType.OAUTH2);
		});
	}

	@Test
	void theEventCarriesEverythingNeededToDoTheLinking() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(this.published).singleElement()
			.isEqualTo(new InvitationRedeemedEvent(JANE, "jane", IDENTITY, invitation.token()));
	}

	@Test
	void anInvitationWithNoRolesFallsBackToTheConfiguredDefaults() {
		// Without this an admitted principal arrives with OIDC_USER and SCOPE_* and no
		// ROLE_ at all, then gets refused by every hasRole() rule — exactly the bug #5
		// fixed.
		this.properties.getApproval().setDefaultRoles(new java.util.ArrayList<>(List.of("USER")));
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");

		redemption((event) -> this.published.add(event)).admit(requestHolding(invitation.token()), JANE, IDENTITY,
				AuthProviderType.OAUTH2);

		assertThat(this.approvals.find(JANE)).get().extracting(org.alexmond.uniauth.approval.ApprovalRecord::roles)
			.isEqualTo(List.of("USER"));
	}

	@Test
	void theTokenIsClearedFromTheSessionOnceClaimed() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void aRequestHoldingNoTokenIsNotAdmittedAndNothingIsWritten() {
		boolean admitted = redemption((event) -> this.published.add(event)).admit(new MockHttpServletRequest(), JANE,
				IDENTITY, AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
		assertThat(this.published).isEmpty();
	}

	@Test
	void aSecondPrincipalCannotClaimTheSameInvitationAndTheTokenIsDropped() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		redemption((event) -> this.published.add(event)).admit(requestHolding(invitation.token()), JANE, IDENTITY,
				AuthProviderType.OAUTH2);
		MockHttpServletRequest bobsRequest = requestHolding(invitation.token());

		boolean admitted = redemption((event) -> this.published.add(event)).admit(bobsRequest, BOB,
				PrincipalIdentity.ofName("bob-sub"), AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.UNKNOWN);
		// Dropped, so Bob is not re-attempting a dead token on every single request for
		// the life of his session.
		assertThat(Invitations.pending(bobsRequest)).isNull();
	}

	@Test
	void aListenerThatThrowsLeavesThePrincipalUnadmitted() {
		// Admitted-but-unlinked is worse than "try again": the person would be browsing
		// as nobody, holding a session no record backs.
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");

		boolean admitted = redemption((event) -> {
			throw new IllegalStateException("no such record");
		}).admit(requestHolding(invitation.token()), JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.PENDING);
	}

	@Test
	void afterAFailedListenerTheNextRequestRetriesAndSucceeds() {
		// The reason redeem is keyed by principal. If the claim made the token dead, one
		// transient failure would strand Jane with a URL that can never work again and no
		// way back except an administrator noticing.
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());
		redemption((event) -> {
			throw new IllegalStateException("the database was down");
		}).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);
		assertThat(Invitations.pending(request)).isNotNull();

		boolean admitted = redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY,
				AuthProviderType.OAUTH2);

		assertThat(admitted).isTrue();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get().extracting(org.alexmond.uniauth.approval.ApprovalRecord::roles)
			.isEqualTo(List.of("FAMILY"));
	}

	@Test
	void aRevokedInvitationIsNotRedeemedAndTheTokenIsDropped() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		this.invitations.revoke(invitation.token(), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		assertThat(redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY,
				AuthProviderType.OAUTH2))
			.isFalse();
		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void manySimultaneousRequestsFromTheSamePrincipalAdmitThemOnceAndWriteOneApproval() throws Exception {
		// Review Focus 4, the double-click, through the whole collaborator rather than
		// only the store.
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		int attempts = 8;
		CountDownLatch startLine = new CountDownLatch(1);
		AtomicInteger admitted = new AtomicInteger();
		List<Object> events = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
		InvitationRedemption redemption = redemption(events::add);
		ExecutorService pool = Executors.newFixedThreadPool(attempts);
		try {
			for (int i = 0; i < attempts; i++) {
				MockHttpServletRequest request = requestHolding(invitation.token());
				pool.submit(() -> {
					try {
						startLine.await();
						if (redemption.admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2)) {
							admitted.incrementAndGet();
						}
					}
					catch (InterruptedException interrupted) {
						Thread.currentThread().interrupt();
					}
				});
			}
			startLine.countDown();
			pool.shutdown();
			assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
		}
		finally {
			pool.shutdownNow();
		}

		// Every one is the same person, so every one succeeds; the record settles once.
		assertThat(admitted.get()).isEqualTo(attempts);
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get().extracting(org.alexmond.uniauth.approval.ApprovalRecord::roles)
			.isEqualTo(List.of("FAMILY"));
	}

	private MockHttpServletRequest requestHolding(InvitationToken token) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		Invitations.stash(request, token);
		return request;
	}

	private InvitationRedemption redemption(java.util.function.Consumer<Object> publisher) {
		return new InvitationRedemption(this.invitations, this.approvals, publisher::accept, this.properties);
	}

}
```

- [ ] **Step 2: Run the test and watch it fail**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InvitationRedemptionTest
```

Expected: compilation failure — `cannot find symbol: class Invitations`.

- [ ] **Step 3: Write `InvitationRedeemedEvent`**

```java
package org.alexmond.uniauth.invitation;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.PrincipalIdentity;

/**
 * Says that a principal has claimed an invitation, so the application can attach the login
 * to its own record.
 *
 * <p>
 * <strong>Published synchronously inside the authorization decision, and a listener that
 * throws fails the admission.</strong> That is an unusual contract for a Spring event and
 * it is deliberate: admitted-but-unlinked is worse than "try again", because the person
 * would be browsing as nobody, holding a session that no record backs. On a throw the
 * principal stays pending and the request is refused.
 *
 * <p>
 * Retrying is safe and is the expected recovery. The invitation stays claimed by this same
 * principal, so the next request redeems again as a no-op and admits them once the
 * application has recovered — which is why one-use is keyed by principal rather than by
 * request.
 *
 * <p>
 * The link is also durable without any listener at all: {@code Invitation.usedBy} records
 * which key claimed which {@code subjectRef}, permanently. An application that would rather
 * query the store than listen can.
 *
 * @param key the approval key the principal was admitted under — {@code (provider, subject)}
 * @param subjectRef the application's own identifier for the person, straight off the
 * invitation and never interpreted by UniAuth
 * @param identity who the provider says they are, for a listener that wants to store a
 * display name or address alongside the link
 * @param token the invitation claimed, for the application's own audit trail
 */
public record InvitationRedeemedEvent(ApprovalKey key, String subjectRef, PrincipalIdentity identity,
		InvitationToken token) {
}
```

- [ ] **Step 4: Write `Invitations`**

```java
package org.alexmond.uniauth.invitation;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Carries an invitation across the provider round trip, in the session.
 *
 * <p>
 * The session is the only place it can go. The token has to survive a redirect out to
 * Google or an identity provider and back, and the alternatives are per-mechanism: OAuth2
 * has {@code state}, SAML has {@code RelayState}, form login has neither. Using them would
 * mean three implementations of one idea, which is the split the single chain exists to
 * avoid.
 *
 * <p>
 * The cost is that a session lost mid-login loses the token. That is a real case — sessions
 * are in memory, which is why the deployments are {@code Recreate} — and the recovery is
 * the invitation URL itself: it is still unclaimed, so reopening it claims it directly,
 * without a second sign-in.
 */
public final class Invitations {

	/** Where the pending token sits on the session. */
	public static final String SESSION_ATTRIBUTE = Invitations.class.getName() + ".TOKEN";

	private Invitations() {
	}

	/**
	 * Remembers a validated token for the rest of this session.
	 * @param request the request whose session should carry it
	 * @param token the token to carry
	 */
	public static void stash(HttpServletRequest request, InvitationToken token) {
		request.getSession(true).setAttribute(SESSION_ATTRIBUTE, token);
	}

	/**
	 * The token this session is carrying, if any.
	 * @param request the request to read
	 * @return the token, or {@code null} when there is none. Deliberately does not create
	 * a session: this is called on every authorized request, and creating one for each
	 * would turn a stateless API call into a stateful one
	 */
	public static InvitationToken pending(HttpServletRequest request) {
		if (request == null) {
			return null;
		}
		HttpSession session = request.getSession(false);
		return (session != null) ? (InvitationToken) session.getAttribute(SESSION_ATTRIBUTE) : null;
	}

	/**
	 * Forgets the token.
	 *
	 * <p>
	 * Called both when it is claimed and when it turns out to be unusable — leaving a dead
	 * token behind would have the gate re-attempt it on every request for the life of the
	 * session.
	 * @param request the request whose session should forget it
	 */
	public static void clear(HttpServletRequest request) {
		if (request == null) {
			return;
		}
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.removeAttribute(SESSION_ATTRIBUTE);
		}
	}

}
```

- [ ] **Step 5: Write `InvitationRedemption`**

```java
package org.alexmond.uniauth.invitation;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.PrincipalIdentity;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.ApplicationEventPublisher;

/**
 * Turns a stashed invitation token into an approval.
 *
 * <p>
 * Separate from the authorization manager so the ordering can be read in one place,
 * because the ordering is the part that matters: claim, then publish, then approve. The
 * event goes out <em>before</em> the approval is written, so a listener that throws leaves
 * the principal pending rather than admitted-and-unlinked. The claim stays, keyed to this
 * principal, so the next request retries.
 */
public class InvitationRedemption {

	private static final Logger LOGGER = LoggerFactory.getLogger(InvitationRedemption.class);

	private final InvitationStore invitations;

	private final ApprovalStore approvals;

	private final ApplicationEventPublisher events;

	private final UniAuthProperties properties;

	/**
	 * Creates the collaborator.
	 * @param invitations where invitations are claimed
	 * @param approvals where the resulting decision is written
	 * @param events publisher for the linking event
	 * @param properties supplies the fallback roles
	 */
	public InvitationRedemption(InvitationStore invitations, ApprovalStore approvals,
			ApplicationEventPublisher events, UniAuthProperties properties) {
		this.invitations = invitations;
		this.approvals = approvals;
		this.events = events;
		this.properties = properties;
	}

	/**
	 * Claims whatever invitation this session is carrying, and admits the principal.
	 *
	 * <p>
	 * Called on an authenticated request whatever the principal's current standing, not
	 * only on a first sighting. Someone whose session survived the round trip arrives
	 * {@code UNKNOWN}; someone whose pod restarted mid-login arrives {@code PENDING} and
	 * reopens the URL; someone already signed in confirms on the invitation page. All
	 * three have to work, and conditioning on {@code UNKNOWN} would break the last two.
	 * @param request the current request, whose session may carry a token
	 * @param key who is asking
	 * @param identity who the provider says they are, recorded so the decision reads like
	 * any other
	 * @param mechanism which mechanism vouched for them
	 * @return {@code true} when the principal is now approved; {@code false} when there
	 * was nothing to claim, the invitation was not claimable, or a listener refused
	 */
	public boolean admit(HttpServletRequest request, ApprovalKey key, PrincipalIdentity identity,
			AuthProviderType mechanism) {
		InvitationToken token = Invitations.pending(request);
		if (token == null) {
			return false;
		}
		Invitation claimed;
		try {
			claimed = this.invitations.redeem(token, key);
		}
		catch (InvitationStore.InvitationNotRedeemableException refused) {
			// Expired, revoked, or somebody else got there first. Drop the token so the
			// gate is not re-attempting a dead one on every request of this session.
			LOGGER.debug("An invitation could not be claimed by {}: {}", key, refused.getMessage());
			Invitations.clear(request);
			return false;
		}
		// Recorded before the event so there is something for decide() to settle, and so
		// a refusing listener leaves a visible PENDING rather than nothing at all.
		this.approvals.recordPending(key, identity, mechanism);
		try {
			this.events.publishEvent(new InvitationRedeemedEvent(key, claimed.subjectRef(), identity, token));
		}
		catch (RuntimeException failed) {
			// Deliberately not approved. The claim stands and is keyed to this principal,
			// so the next request retries and gets in once the application recovers.
			LOGGER.warn("A listener refused the invitation link for {} (subjectRef '{}'); "
					+ "the principal stays pending and the next request will retry", key, claimed.subjectRef(),
					failed);
			return false;
		}
		this.approvals.decide(key, ApprovalStatus.APPROVED, "invitation:" + claimed.subjectRef(), rolesFor(claimed));
		Invitations.clear(request);
		return true;
	}

	/**
	 * The invitation's roles, or the configured defaults.
	 *
	 * <p>
	 * An approval granting nothing reproduces the bug #5 fixed: a federated principal
	 * arrives with {@code OIDC_USER} and {@code SCOPE_*} and no {@code ROLE_} at all, so
	 * they clear the gate and are then refused by every role rule in the application.
	 */
	private List<String> rolesFor(Invitation invitation) {
		return !invitation.roles().isEmpty() ? invitation.roles()
				: List.copyOf(this.properties.getApproval().getDefaultRoles());
	}

}
```

- [ ] **Step 6: Format, then run the test and watch it pass**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/mvnw -q -f /home/alexm/IdeaProjects/uniauth/pom.xml spring-javaformat:apply
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InvitationRedemptionTest
```

Expected: PASS, 10 tests.

- [ ] **Step 7: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/invitation uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/invitation
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
feat(invitations): the linking event and the redemption collaborator (#29)

Claim, then publish, then approve. The event goes out before the approval is
written, so a listener that throws leaves the principal pending rather than
admitted-and-unlinked — browsing as nobody, holding a session no record
backs. The claim stands and is keyed to the principal, so the next request
retries.

The approver is recorded as "invitation:<subjectRef>", not the token: a
bearer credential has no business in an audit record, and the subjectRef is
what an auditor wants to read.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

### Task 5: Redemption and `invite-only` in the authorization manager

**Files:**
- Modify: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/approval/ApprovalAuthorizationManager.java`
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/approval/ApprovalAuthorizationManagerTest.java` (new)

**Interfaces:**
- Consumes: `InvitationRedemption.admit(...)` (Task 4); `UniAuthProperties.Approval.Invitations.isInviteOnly()` (Task 3).
- Produces: a second constructor `ApprovalAuthorizationManager(ApprovalStore, MechanismResolver, UniAuthProperties, InvitationRedemption)` where the collaborator may be `null`. The existing three-argument constructor stays, delegating with `null`.

**Why both constructors.** `ApprovalAuthorizationManager` is published API in a released starter, and an application that constructs its own would break on a widened signature. Keeping the old one is also what makes invitations invisible when they are off: the collaborator is `null` and the method short-circuits.

**Where in `authorize`.** Redemption runs *after* the mechanism gate (`requireFor`) and *before* the status is read, because the point is to change the status. `invite-only` applies only when redemption did not admit them and the status is `UNKNOWN` — a principal already `PENDING` was recorded under an earlier configuration, and silently flipping them to `DENIED` would revoke someone who is waiting.

- [ ] **Step 1: Write the failing test**

Create `ApprovalAuthorizationManagerTest.java`:

```java
package org.alexmond.uniauth.approval;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InMemoryInvitationStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.Invitations;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The gate, with invitations in play.
 *
 * <p>
 * Driven directly rather than through the chain, because the cases that matter are
 * combinations of standing, stashed token and {@code invite-only} — there are more of them
 * than it is worth booting a context for, and the chain-level proof lives in
 * {@code UniAuthInvitationTest}.
 */
class ApprovalAuthorizationManagerTest {

	private static final ApprovalKey ALICE = new ApprovalKey("internal", "alice");

	private ApprovalStore approvals;

	private InvitationStore invitations;

	private UniAuthProperties properties;

	@BeforeEach
	void freshCollaborators() {
		this.approvals = new InMemoryApprovalStore();
		this.invitations = new InMemoryInvitationStore(Clock.systemUTC(), Duration.ofDays(14));
		this.properties = new UniAuthProperties();
		this.properties.getApproval().setRequireFor(new java.util.ArrayList<>(List.of(AuthProviderType.INTERNAL)));
		this.properties.getApproval().getInvitations().setEnabled(true);
	}

	@Test
	void anInvitedPrincipalIsLetThroughOnTheFirstRequestWithNoPendingStep() {
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();
		Invitations.stash(request, invitation.token());

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isTrue();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(request.getAttribute(ApprovalAuthorizationManager.PENDING_ATTRIBUTE)).isNull();
	}

	@Test
	void anUninvitedPrincipalIsStillHeldPendingAsBefore() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isFalse();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.PENDING);
		assertThat(request.getAttribute(ApprovalAuthorizationManager.PENDING_ATTRIBUTE)).isEqualTo(Boolean.TRUE);
	}

	@Test
	void anAlreadyPendingPrincipalCanStillClaimAnInvitation() {
		// The restart case. The session was lost mid-login, so they landed as PENDING;
		// reopening the URL has to work, and conditioning redemption on UNKNOWN would
		// mean it never does.
		this.approvals.recordPending(ALICE, PrincipalIdentity.ofName("alice"), AuthProviderType.INTERNAL);
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();
		Invitations.stash(request, invitation.token());

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isTrue();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void inviteOnlyRefusesAnUninvitedPrincipalOutrightRatherThanHoldingThem() {
		this.properties.getApproval().getInvitations().setInviteOnly(true);
		MockHttpServletRequest request = new MockHttpServletRequest();

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isFalse();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.DENIED);
		// Not flagged, so the access-denied handler leaves it a plain 403. Telling
		// somebody who will never be admitted to keep waiting is a lie.
		assertThat(request.getAttribute(ApprovalAuthorizationManager.PENDING_ATTRIBUTE)).isNull();
	}

	@Test
	void inviteOnlyRecordsWhyTheRefusalHappened() {
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(this.approvals.find(ALICE)).get().extracting(ApprovalRecord::decidedBy).isEqualTo("invite-only");
	}

	@Test
	void inviteOnlyDoesNotRevokeSomebodyAlreadyWaiting() {
		// They were recorded under an earlier configuration. Flipping a waiting person to
		// DENIED turns a queue a human was about to read into a silent refusal.
		this.approvals.recordPending(ALICE, PrincipalIdentity.ofName("alice"), AuthProviderType.INTERNAL);
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.PENDING);
	}

	@Test
	void inviteOnlyDoesNotTouchAnAlreadyApprovedPrincipal() {
		this.approvals.recordPending(ALICE, PrincipalIdentity.ofName("alice"), AuthProviderType.INTERNAL);
		this.approvals.decide(ALICE, ApprovalStatus.APPROVED, "admin", List.of("USER"));
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void anUngatedMechanismIsNotSubjectToInviteOnlyEither() {
		this.properties.getApproval().setRequireFor(new java.util.ArrayList<>(List.of(AuthProviderType.OAUTH2)));
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isTrue();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.UNKNOWN);
	}

	@Test
	void anonymousRequestsAreStillRefusedSoTheEntryPointRedirects() {
		AuthorizationDecision decision = manager().authorize(
				() -> new AnonymousAuthenticationToken("key", "anonymousUser",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")),
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void withNoRedemptionCollaboratorTheGateBehavesExactlyAsItDidBefore() {
		// Invitations switched off: the three-argument constructor is what
		// ApprovalConfiguration used before this feature, and it must still hold.
		ApprovalAuthorizationManager plain = new ApprovalAuthorizationManager(this.approvals, new MechanismResolver(),
				this.properties);
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		AuthorizationDecision decision = plain.authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isFalse();
		// PENDING, not DENIED: invite-only cannot mean anything without invitations.
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.PENDING);
	}

	private ApprovalAuthorizationManager manager() {
		InvitationRedemption redemption = new InvitationRedemption(this.invitations, this.approvals, (event) -> {
		}, this.properties);
		return new ApprovalAuthorizationManager(this.approvals, new MechanismResolver(), this.properties, redemption);
	}

	private static Authentication alice() {
		return UsernamePasswordAuthenticationToken.authenticated("alice", "n/a",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
	}

}
```

- [ ] **Step 2: Run the test and watch it fail**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh ApprovalAuthorizationManagerTest
```

Expected: compilation failure — no four-argument constructor.

- [ ] **Step 3: Add the collaborator to the manager**

In `ApprovalAuthorizationManager.java`, add the import `org.alexmond.uniauth.invitation.InvitationRedemption;`, add the field after `identities`:

```java
	private final InvitationRedemption redemption;
```

Replace the existing constructor with these two:

```java
	/**
	 * Creates the gate without invitations.
	 * @param store where standing is recorded and read
	 * @param resolver works out which provider answered, since approval is per provider
	 * @param properties supplies which mechanisms the gate applies to
	 */
	public ApprovalAuthorizationManager(ApprovalStore store, MechanismResolver resolver,
			UniAuthProperties properties) {
		this(store, resolver, properties, null);
	}

	/**
	 * Creates the gate.
	 *
	 * <p>
	 * The three-argument constructor is kept rather than widened because this class is
	 * published API: an application that builds its own gate should not break on a feature
	 * it does not use.
	 * @param store where standing is recorded and read
	 * @param resolver works out which provider answered, since approval is per provider
	 * @param properties supplies which mechanisms the gate applies to
	 * @param redemption claims an invitation the session is carrying, or {@code null} when
	 * invitations are switched off — in which case this class behaves exactly as it did
	 * before they existed, {@code invite-only} included, since that setting cannot mean
	 * anything without them
	 */
	public ApprovalAuthorizationManager(ApprovalStore store, MechanismResolver resolver, UniAuthProperties properties,
			InvitationRedemption redemption) {
		this.store = store;
		this.resolver = resolver;
		this.properties = properties;
		this.redemption = redemption;
	}
```

Replace the body of `authorize` from the `ApprovalKey key = ...` line onwards with:

```java
		ApprovalKey key = ApprovalKey.of(mechanism, current);
		PrincipalIdentity identity = this.identities.resolve(current);
		// Before the status is read, because claiming an invitation is what changes it.
		// Runs whatever the current standing: a session that survived the round trip
		// arrives UNKNOWN, one lost to a restart arrives PENDING and reopens the URL, and
		// somebody already signed in confirms on the invitation page. All three have to
		// work.
		if (this.redemption != null
				&& this.redemption.admit(context.getRequest(), key, identity, mechanism.type())) {
			return new AuthorizationDecision(true);
		}
		ApprovalStatus status = this.store.statusOf(key);
		if (status == ApprovalStatus.UNKNOWN) {
			// Resolved here, at the one moment the principal is present. The queue is
			// read later, by someone else, when this session may be long gone.
			this.store.recordPending(key, identity, mechanism.type());
			status = inviteOnly() ? refuse(key) : ApprovalStatus.PENDING;
		}
		if (status == ApprovalStatus.APPROVED) {
			return new AuthorizationDecision(true);
		}
		markPending(context.getRequest(), status);
		return new AuthorizationDecision(false);
```

And add these two private methods beside `markPending`:

```java
	/**
	 * Whether an uninvited principal should be refused outright.
	 *
	 * <p>
	 * Only meaningful with invitations switched on: without them nobody can be invited, so
	 * honouring the flag would lock out every user of an application that set it by
	 * accident.
	 */
	private boolean inviteOnly() {
		return this.redemption != null && this.properties.getApproval().getInvitations().isInviteOnly();
	}

	/**
	 * Records a refusal for somebody who will not be admitted.
	 *
	 * <p>
	 * Only ever applied to a principal seen for the first time. Somebody already waiting
	 * was recorded under an earlier configuration, and flipping them to {@code DENIED}
	 * would turn a queue a human was about to read into a silent refusal.
	 */
	private ApprovalStatus refuse(ApprovalKey key) {
		this.store.decide(key, ApprovalStatus.DENIED, "invite-only", java.util.List.of());
		return ApprovalStatus.DENIED;
	}
```

- [ ] **Step 4: Format, then run the test and watch it pass**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/mvnw -q -f /home/alexm/IdeaProjects/uniauth/pom.xml spring-javaformat:apply
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh 'ApprovalAuthorizationManagerTest,UniAuthApprovalTest'
```

Expected: PASS. `UniAuthApprovalTest` is in the list because this task edits the gate every one of its 14 tests runs through; it must stay green untouched.

- [ ] **Step 5: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/approval uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/approval
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
feat(invitations): redeem in the authorization manager, and invite-only (#29)

Here for the reason first sightings are already here: four mechanisms would
mean four success handlers, and every request passes authorization exactly
once. Redemption runs whatever the principal's current standing — a session
that survived the round trip arrives UNKNOWN, one lost to a restart arrives
PENDING and reopens the URL, and somebody already signed in confirms on the
invitation page.

invite-only records DENIED, which the access-denied handler already renders
as a plain 403: telling somebody who will never be admitted to keep waiting
is a lie. It only ever applies to a first sighting — flipping a waiting
person to DENIED would turn a queue a human was about to read into a silent
refusal.

The three-argument constructor stays. This class is published API, and an
application building its own gate should not break on a feature it does not
use.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

### Task 6: The endpoint, the confirmation page, and the chooser's notice

**Files:**
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/web/UniAuthInvitationController.java`
- Create: `uniauth-spring-boot-starter/src/main/resources/templates/uniauth/invite.html`
- Modify: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/web/UniAuthLoginController.java` — the `invite` request parameter
- Modify: `uniauth-spring-boot-starter/src/main/resources/templates/uniauth/login.html` — one notice line
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/web/UniAuthInvitationControllerTest.java` (new)

**Interfaces:**
- Consumes: `InvitationStore`, `Invitation`, `InvitationStatus`, `InvitationToken` (Task 2); `Invitations.stash` (Task 4); `UniAuthProperties` (Task 3).
- Produces: `new UniAuthInvitationController(InvitationStore, UniAuthProperties, Clock)`; the view name `uniauth/invite` with model attributes `signedInAs`, `invitePath`, `token`; and the chooser's `invite` model attribute carrying `unknown | used | expired | revoked`.

**Review Focus item 2 lands here:** a garbage token.

**No new outcome page, deliberately.** #11 happened because the starter redirected to a page it never served and the consumer got `ERR_TOO_MANY_REDIRECTS`. An `outcome-page` property would be the same mistake with a new name. The chooser already exists and is already served, so the outcome goes there as a query parameter.

**`REVOKED` gets its own reason** rather than being folded into `unknown`, which the spec's three-value list would have done. Somebody whose invitation was withdrawn is in a different position from somebody holding a typo, and the person who withdrew it is who they will ask.

- [ ] **Step 1: Write the failing test**

Create `UniAuthInvitationControllerTest.java`:

```java
package org.alexmond.uniauth.web;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InMemoryInvitationStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationToken;
import org.alexmond.uniauth.invitation.Invitations;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The endpoint, driven directly.
 *
 * <p>
 * The chain-level proof — that the path is permitted and reachable before anybody has
 * logged in — lives in {@code UniAuthInvitationTest}. What is worth testing here is the
 * branching, because there are six outcomes and they turn on two independent things: who
 * is asking, and what state the invitation is in.
 */
class UniAuthInvitationControllerTest {

	private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

	private InMemoryInvitationStore store;

	private UniAuthProperties properties;

	private UniAuthInvitationController controller;

	@BeforeEach
	void freshController() {
		this.store = new InMemoryInvitationStore(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(14));
		this.properties = new UniAuthProperties();
		this.controller = new UniAuthInvitationController(this.store, this.properties,
				Clock.fixed(NOW, ZoneOffset.UTC));
	}

	@Test
	void anAnonymousVisitorWithAnOpenInvitationIsStashedAndSentToTheChooser() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();

		String view = this.controller.open(invitation.token().value(), null, request, new ExtendedModelMap());

		assertThat(view).isEqualTo("redirect:/login");
		assertThat(Invitations.pending(request)).isEqualTo(invitation.token());
	}

	@Test
	void anUnknownTokenGoesToTheChooserWithAReasonRatherThanAPageTheStarterDoesNotServe() {
		// Review Focus 2, and the shape of #11: a redirect to an unserved page gave a
		// consumer ERR_TOO_MANY_REDIRECTS. The chooser is already served.
		MockHttpServletRequest request = new MockHttpServletRequest();

		String view = this.controller.open("not-a-real-token", null, request, new ExtendedModelMap());

		assertThat(view).isEqualTo("redirect:/login?invite=unknown");
		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void tokenShapedJunkIsStillJustUnknown() {
		// Review Focus 2. A scanner, a truncated copy-paste, a blank segment — none of
		// these may become a 500 or escape the path.
		for (String junk : List.of("../../etc/passwd", "%00", "  ", "a".repeat(10_000), "<script>")) {
			assertThat(this.controller.open(junk, null, new MockHttpServletRequest(), new ExtendedModelMap()))
				.isEqualTo("redirect:/login?invite=unknown");
		}
	}

	@Test
	void aUsedInvitationSaysSo() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(invitation.token(), new ApprovalKey("google", "someone"));

		assertThat(this.controller.open(invitation.token().value(), null, new MockHttpServletRequest(),
				new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=used");
	}

	@Test
	void anExpiredInvitationSaysSo() {
		Invitation invitation = this.store.create("jane", Duration.ofSeconds(1), List.of(), "admin");
		UniAuthInvitationController later = new UniAuthInvitationController(this.store, this.properties,
				Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC));

		assertThat(later.open(invitation.token().value(), null, new MockHttpServletRequest(), new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=expired");
	}

	@Test
	void aRevokedInvitationSaysRevokedRatherThanUnknown() {
		// Somebody whose invitation was withdrawn is in a different position from somebody
		// holding a typo, and they will go and ask the person who withdrew it.
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.revoke(invitation.token(), "admin");

		assertThat(this.controller.open(invitation.token().value(), null, new MockHttpServletRequest(),
				new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=revoked");
	}

	@Test
	void theChooserPathIsWhicheverTheApplicationConfigured() {
		this.properties.setLoginPage("/sign-in");

		assertThat(this.controller.open("nope", null, new MockHttpServletRequest(), new ExtendedModelMap()))
			.isEqualTo("redirect:/sign-in?invite=unknown");
	}

	@Test
	void anAuthenticatedVisitorGetsAConfirmationPageRatherThanBeingClaimedSilently() {
		// The URL is the credential, so whoever holds it gets Jane's record. That cannot
		// be designed away; what it can be is deliberate rather than accidental.
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		Model model = new ExtendedModelMap();

		String view = this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(), model);

		assertThat(view).isEqualTo("uniauth/invite");
		assertThat(model.getAttribute("signedInAs")).isEqualTo("bob@example.com");
		assertThat(model.getAttribute("token")).isEqualTo(invitation.token().value());
		assertThat(model.getAttribute("invitePath")).isEqualTo("/invite/{token}");
	}

	@Test
	void theConfirmationPageDoesNotRevealWhoTheInvitationNames() {
		// The visitor may not be the invited person. The subjectRef is the application's
		// own identifier for somebody else, and the page does not need it to do its job.
		Invitation invitation = this.store.create("jane-record-4417", null, List.of(), "admin");
		Model model = new ExtendedModelMap();

		this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(), model);

		assertThat(model.asMap().values()).noneSatisfy(
				(value) -> assertThat(String.valueOf(value)).contains("jane-record-4417"));
	}

	@Test
	void theGetDoesNotClaimAnythingEvenForAnAuthenticatedVisitor() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");

		this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(), new ExtendedModelMap());

		assertThat(this.store.find(invitation.token())).get()
			.satisfies((found) -> assertThat(found.usedBy()).isNull());
	}

	@Test
	void anAuthenticatedVisitorWithADeadInvitationIsSentToTheChooserWithTheReason() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.revoke(invitation.token(), "admin");

		assertThat(this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(),
				new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=revoked");
	}

	@Test
	void confirmingStashesTheTokenAndSendsThemOnSoTheGateClaimsIt() {
		// Redemption stays in the authorization manager, which is the one place every
		// request passes exactly once. The POST only arms it.
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();

		String view = this.controller.confirm(invitation.token().value(), bob(), request);

		assertThat(view).isEqualTo("redirect:/");
		assertThat(Invitations.pending(request)).isEqualTo(invitation.token());
	}

	@Test
	void confirmingSendsThemWhereverTheApplicationConfigured() {
		this.properties.setDefaultSuccessUrl("/dashboard");
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");

		assertThat(this.controller.confirm(invitation.token().value(), bob(), new MockHttpServletRequest()))
			.isEqualTo("redirect:/dashboard");
	}

	@Test
	void confirmingAnAlreadyDeadInvitationGoesToTheChooserAndStashesNothing() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(invitation.token(), new ApprovalKey("google", "someone"));
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(this.controller.confirm(invitation.token().value(), bob(), request))
			.isEqualTo("redirect:/login?invite=used");
		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void anAnonymousPostHasNothingToConfirmAndIsSentToTheChooser() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(this.controller.confirm(invitation.token().value(), null, request)).isEqualTo("redirect:/login");
		// Stashed anyway: they are about to sign in, and that is exactly the flow.
		assertThat(Invitations.pending(request)).isEqualTo(invitation.token());
	}

	private static org.springframework.security.core.Authentication bob() {
		return org.springframework.security.authentication.UsernamePasswordAuthenticationToken
			.authenticated("bob@example.com", "n/a",
					org.springframework.security.core.authority.AuthorityUtils.createAuthorityList("ROLE_USER"));
	}

}
```

- [ ] **Step 2: Run the test and watch it fail**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh UniAuthInvitationControllerTest
```

Expected: compilation failure — `cannot find symbol: class UniAuthInvitationController`.

- [ ] **Step 3: Write `UniAuthInvitationController`**

```java
package org.alexmond.uniauth.web;

import java.time.Clock;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationStatus;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.InvitationToken;
import org.alexmond.uniauth.invitation.Invitations;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Where an invitation URL lands.
 *
 * <p>
 * It does not claim anything. Redemption lives in {@code ApprovalAuthorizationManager},
 * the one place every request passes exactly once; this endpoint only validates the token
 * and puts it on the session, so the ordinary sign-in follows and the gate does the rest.
 * Four mechanisms would otherwise mean four success handlers.
 *
 * <p>
 * The path is permitted on the starter's chain, because it has to work before anybody has
 * logged in. A token that is not usable goes to the chooser with a {@code ?invite=} reason
 * rather than to a page of its own — #11 happened because the starter redirected somewhere
 * it never served, and the consumer got {@code ERR_TOO_MANY_REDIRECTS}. An
 * {@code outcome-page} property would be that mistake with a new name.
 *
 * <p>
 * Registered as a bean rather than component-scanned, so {@code uniauth.enabled=false}
 * genuinely backs off.
 */
@Controller
public class UniAuthInvitationController {

	private final InvitationStore store;

	private final UniAuthProperties properties;

	private final Clock clock;

	/**
	 * Creates the controller.
	 * @param store where invitations are looked up
	 * @param properties supplies the chooser path, the success path, and the configured
	 * invitation path the confirmation form posts back to
	 * @param clock judges expiry; injectable so a test need not sleep
	 */
	public UniAuthInvitationController(InvitationStore store, UniAuthProperties properties, Clock clock) {
		this.store = store;
		this.properties = properties;
		this.clock = clock;
	}

	/**
	 * Opens an invitation.
	 *
	 * <p>
	 * An anonymous visitor is stashed and sent to the chooser, which is the ordinary flow.
	 * An authenticated one gets a confirmation page instead, because the URL is the
	 * credential: whoever holds it gets the record it names, and that is inherent to link
	 * invitations. What the page buys is that a hijack — or a mis-sent link opened by the
	 * wrong colleague — is deliberate rather than accidental. It doubles as the recovery
	 * path for a session lost mid-login: the invitation is still unclaimed, so confirming
	 * claims it without a second sign-in.
	 * @param token the token from the path
	 * @param authentication whoever is asking, {@code null} when nobody is
	 * @param request the current request, whose session carries the token onwards
	 * @param model receives what the confirmation page renders
	 * @return a redirect, or the confirmation view
	 */
	@GetMapping("${uniauth.approval.invitations.path:/invite/{token}}")
	public String open(@PathVariable String token, @CurrentSecurityContext(expression = "authentication")
			Authentication authentication, HttpServletRequest request, Model model) {
		Optional<Invitation> open = usable(token);
		if (open.isEmpty()) {
			return chooser(reasonFor(token));
		}
		if (!isAuthenticated(authentication)) {
			Invitations.stash(request, open.get().token());
			return chooser(null);
		}
		model.addAttribute("signedInAs", authentication.getName());
		model.addAttribute("invitePath", this.properties.getApproval().getInvitations().getPath());
		model.addAttribute("token", open.get().token().value());
		// Deliberately not the subjectRef. The visitor may not be the invited person, and
		// it is the application's own identifier for somebody else.
		return "uniauth/invite";
	}

	/**
	 * Accepts the confirmation.
	 *
	 * <p>
	 * Stashes the token and sends the caller on. The next request passes authorization,
	 * and that is where the claim happens.
	 * @param token the token from the path
	 * @param authentication whoever confirmed, {@code null} when nobody is signed in — in
	 * which case there was nothing to confirm, and they are sent to the chooser to sign in
	 * as the flow intends
	 * @param request the current request, whose session carries the token onwards
	 * @return a redirect
	 */
	@PostMapping("${uniauth.approval.invitations.path:/invite/{token}}")
	public String confirm(@PathVariable String token, @CurrentSecurityContext(expression = "authentication")
			Authentication authentication, HttpServletRequest request) {
		Optional<Invitation> open = usable(token);
		if (open.isEmpty()) {
			return chooser(reasonFor(token));
		}
		Invitations.stash(request, open.get().token());
		return isAuthenticated(authentication) ? "redirect:" + this.properties.getDefaultSuccessUrl()
				: chooser(null);
	}

	/**
	 * The invitation behind a token, if it can still be used.
	 *
	 * <p>
	 * Every rejection collapses to {@link Optional#empty}, including token text that is
	 * blank or absurd. A token arriving from a URL is attacker-controlled and most of them
	 * are typos and scanners, so none of it may become an error page.
	 */
	private Optional<Invitation> usable(String token) {
		if (!StringUtils.hasText(token)) {
			return Optional.empty();
		}
		return this.store.find(InvitationToken.of(token))
			.filter((invitation) -> invitation.status(this.clock.instant()) == InvitationStatus.OPEN);
	}

	/** The reason to show, for a token that could not be used. */
	private String reasonFor(String token) {
		if (!StringUtils.hasText(token)) {
			return "unknown";
		}
		return this.store.find(InvitationToken.of(token))
			.map((invitation) -> invitation.status(this.clock.instant()).name().toLowerCase(java.util.Locale.ROOT))
			.orElse("unknown");
	}

	/**
	 * A redirect to the chooser, which the starter definitely serves.
	 *
	 * <p>
	 * Returned as a view name rather than written with {@code sendRedirect}, so Spring
	 * prepends the servlet context path — an application mounted under one would otherwise
	 * send its visitors outside itself.
	 */
	private String chooser(String reason) {
		String path = this.properties.getLoginPage();
		return (reason != null) ? "redirect:" + path + "?invite=" + reason : "redirect:" + path;
	}

	private static boolean isAuthenticated(Authentication authentication) {
		return authentication != null && authentication.isAuthenticated() && !(authentication
			instanceof org.springframework.security.authentication.AnonymousAuthenticationToken);
	}

}
```

- [ ] **Step 4: Write `invite.html`**

Create `uniauth-spring-boot-starter/src/main/resources/templates/uniauth/invite.html`, reusing the chooser's styles so a re-skinned application only has one look to maintain:

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Accept invitation</title>
    <style>
        :root { --muted: #6b7280; --border: #d7dae0; --ink: #16181d; }
        * { box-sizing: border-box; }
        body {
            margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
            padding: 1.5rem; background: #f6f7f9; color: var(--ink);
            font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
        }
        .card {
            width: 100%; max-width: 24rem; padding: 2rem; background: #fff;
            border: 1px solid var(--border); border-radius: 10px;
        }
        h1 { margin: 0 0 1rem; font-size: 1.25rem; }
        p { margin: 0 0 1rem; }
        .who { font-weight: 600; }
        button {
            width: 100%; padding: .7rem; border: 0; border-radius: 6px; cursor: pointer;
            background: var(--ink); color: #fff; font-size: 1rem;
        }
        .hint { margin: .75rem 0 0; font-size: .8125rem; color: var(--muted); }
    </style>
</head>
<body>
<main class="card">
    <h1>Accept this invitation</h1>

    <p>
        You are signed in as <span class="who" th:text="${signedInAs}">someone</span>.
        Accepting links <em>this</em> account to the invitation.
    </p>

    <!-- th:action is what makes Thymeleaf insert the CSRF token; a plain action attribute
         would post without one and be rejected. -->
    <form th:action="@{${invitePath}(token=${token})}" method="post">
        <button type="submit">Accept as <span th:text="${signedInAs}">someone</span></button>
    </form>

    <p class="hint">
        If this invitation was not meant for this account, sign out first and open the link
        again. An invitation can only be accepted once.
    </p>
</main>
</body>
</html>
```

- [ ] **Step 5: Add the `invite` parameter to the chooser**

In `UniAuthLoginController.login`, add the parameter and the model attribute:

```java
	public String login(Model model, @RequestParam(required = false) String error,
			@RequestParam(required = false) String logout, @RequestParam(required = false) String invite) {
```

and, beside the existing `error` / `logout` attributes:

```java
		// The invitation endpoint sends an unusable token here rather than to a page of
		// its own, so the chooser renders the reason. See UniAuthInvitationController.
		model.addAttribute("invite", invite);
```

In `login.html`, after the `logout` notice:

```html
    <div class="notice error" th:if="${invite == 'expired'}">
        That invitation has expired. Ask whoever invited you for a new link.
    </div>
    <div class="notice error" th:if="${invite == 'used'}">
        That invitation has already been used. Ask whoever invited you for a new link.
    </div>
    <div class="notice error" th:if="${invite == 'revoked'}">
        That invitation was withdrawn. Ask whoever invited you if you still need access.
    </div>
    <div class="notice error" th:if="${invite == 'unknown'}">
        That invitation link is not valid. Check you copied the whole URL.
    </div>
```

- [ ] **Step 6: Format, then run the test and watch it pass**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/mvnw -q -f /home/alexm/IdeaProjects/uniauth/pom.xml spring-javaformat:apply
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh UniAuthInvitationControllerTest
```

Expected: PASS, 16 tests.

- [ ] **Step 7: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/web uniauth-spring-boot-starter/src/main/resources/templates/uniauth uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/web
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
feat(invitations): the endpoint, the confirmation page, the chooser notice (#29)

The endpoint claims nothing. It validates the token and puts it on the
session; the gate does the rest, so one implementation covers all four
mechanisms.

An unusable token goes to the chooser with a ?invite= reason rather than to
a page of its own. #11 happened because the starter redirected somewhere it
never served and the consumer got ERR_TOO_MANY_REDIRECTS; an outcome-page
property would be that mistake with a new name.

An authenticated visitor gets a confirmation step. The URL is the
credential, so whoever holds it gets the record it names — that is inherent
to link invitations, and the page is what makes it deliberate rather than
accidental. It does not show the subjectRef: the visitor may not be the
invited person, and it is the application's own identifier for somebody
else.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

### Task 7: Auto-configuration, the permitted path, and the warning

**Files:**
- Create: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/autoconfigure/InvitationConfiguration.java`
- Modify: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/autoconfigure/ApprovalConfiguration.java` — import the new configuration, pass the collaborator to the manager
- Modify: `uniauth-spring-boot-starter/src/main/java/org/alexmond/uniauth/autoconfigure/UniAuthAutoConfiguration.java` — permit the invitation path
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/autoconfigure/InvitationConfigurationTest.java` (new)
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/UniAuthInvitationTest.java` (new)
- Test: `uniauth-spring-boot-starter/src/test/java/org/alexmond/uniauth/UniAuthInviteOnlyTest.java` (new)

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces: beans `uniAuthInvitationStore` (`InvitationStore`), `uniAuthInvitationRedemption` (`InvitationRedemption`), `uniAuthInvitationController` (`UniAuthInvitationController`) — each `@ConditionalOnMissingBean`, all three only when `uniauth.approval.enabled` **and** `uniauth.approval.invitations.enabled` are true.

**Invitations require the approval gate**, because redemption writes an approval record. `InvitationConfiguration` is imported from `ApprovalConfiguration`, so that dependency is structural rather than documented — setting `invitations.enabled` without `approval.enabled` wires nothing, exactly as it would for a mechanism with no registration.

**Verify early:** the controller's `@GetMapping("${uniauth.approval.invitations.path:/invite/{token}}")` relies on Spring's placeholder parser counting the bare `{` in the default value. It should — `PropertyPlaceholderHelper`'s `simplePrefix` is `{`, so the inner braces balance — but `defaultPathResolvesWhenNothingIsConfigured` is the first test in this task precisely so that a wrong reading of that fails loudly here rather than in somebody's deployment. If it does fail, split the property into a prefix (`/invite`) plus a literal `/{token}` in the mapping, and drop `validate()`'s `{token}` rule with it.

- [ ] **Step 1: Write the failing configuration test**

Create `InvitationConfigurationTest.java`:

```java
package org.alexmond.uniauth.autoconfigure;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.InMemoryApprovalStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.invitation.InvitationStatus;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.InvitationToken;
import org.alexmond.uniauth.web.UniAuthInvitationController;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What gets wired, and what gets said about it.
 */
@ExtendWith(OutputCaptureExtension.class)
class InvitationConfigurationTest {

	private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(UniAuthAutoConfiguration.class))
		.withPropertyValues("uniauth.enabled=true", "uniauth.approval.enabled=true");

	@Test
	void nothingIsWiredUntilInvitationsAreAskedFor() {
		this.runner.run((context) -> assertThat(context).hasNotFailed()
			.doesNotHaveBean(InvitationStore.class)
			.doesNotHaveBean(InvitationRedemption.class)
			.doesNotHaveBean(UniAuthInvitationController.class));
	}

	@Test
	void invitationsNeedTheApprovalGateBecauseRedemptionWritesAnApprovalRecord() {
		// Structural rather than documented: InvitationConfiguration is imported from
		// ApprovalConfiguration, so switching invitations on alone wires nothing.
		new WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(UniAuthAutoConfiguration.class))
			.withPropertyValues("uniauth.enabled=true", "uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasNotFailed().doesNotHaveBean(InvitationStore.class));
	}

	@Test
	void askingForInvitationsWiresTheStoreTheCollaboratorAndTheEndpoint() {
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasSingleBean(InvitationStore.class)
				.hasSingleBean(InvitationRedemption.class)
				.hasSingleBean(UniAuthInvitationController.class));
	}

	@Test
	void theDefaultStoreSaysItForgetsEverything(CapturedOutput output) {
		// Durability is the deployment's choice, so this warns rather than refuses — the
		// bargain InMemoryApprovalStore already strikes. But it has to be said: a console
		// pointed at an in-memory store sees only the invitations created in its own
		// process, and that reads as a broken console.
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasNotFailed());

		assertThat(output).contains("InMemoryInvitationStore").contains("lost on restart");
	}

	@Test
	void anApplicationSOwnStoreIsUsedAndNothingIsWarnedAbout(CapturedOutput output) {
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.withUserConfiguration(DurableStore.class)
			.run((context) -> assertThat(context).getBean(InvitationStore.class)
				.isInstanceOf(DurableStore.PretendDatabase.class));

		assertThat(output).doesNotContain("lost on restart");
	}

	@Test
	void aPathWithoutTheTokenPlaceholderFailsTheContextRatherThan404IngForever() {
		// Review Focus 1, at the layer where a person actually hits it.
		this.runner
			.withPropertyValues("uniauth.approval.invitations.enabled=true",
					"uniauth.approval.invitations.path=/invite")
			.run((context) -> assertThat(context).hasFailed()
				.getFailure()
				.rootCause()
				.hasMessageContaining("{token}"));
	}

	@Test
	void defaultPathResolvesWhenNothingIsConfigured() {
		// The mapping's default value contains braces of its own. If Spring's placeholder
		// parser miscounts them the context fails here, loudly, rather than in somebody's
		// deployment.
		this.runner.withPropertyValues("uniauth.approval.invitations.enabled=true")
			.run((context) -> assertThat(context).hasNotFailed().hasSingleBean(UniAuthInvitationController.class));
	}

	@Configuration(proxyBeanMethods = false)
	static class DurableStore {

		@Bean
		InvitationStore applicationsOwnStore() {
			return new PretendDatabase();
		}

		@Bean
		ApprovalStore applicationsOwnApprovals() {
			return new InMemoryApprovalStore();
		}

		/**
		 * Stands in for a database-backed store. Deliberately not a subclass of ours: the
		 * assertion is that the starter backed off, and a subclass would satisfy an
		 * {@code instanceof} against the very class it is meant to have replaced.
		 */
		static class PretendDatabase implements InvitationStore {

			@Override
			public Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy) {
				throw new UnsupportedOperationException();
			}

			@Override
			public Optional<Invitation> find(InvitationToken token) {
				return Optional.empty();
			}

			@Override
			public Invitation redeem(InvitationToken token, ApprovalKey admitted) {
				throw new UnsupportedOperationException();
			}

			@Override
			public void revoke(InvitationToken token, String revokedBy) {
			}

			@Override
			public List<Invitation> list(InvitationStatus... statuses) {
				return List.of();
			}

		}

	}

}
```

- [ ] **Step 2: Run it and watch it fail**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InvitationConfigurationTest
```

Expected: compilation failure, or failures on every assertion about the new beans.

- [ ] **Step 3: Write `InvitationConfiguration`**

```java
package org.alexmond.uniauth.autoconfigure;

import java.time.Clock;

import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InMemoryInvitationStore;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.web.UniAuthInvitationController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires invitations, and only when asked.
 *
 * <p>
 * Imported from {@code ApprovalConfiguration} rather than from the auto-configuration
 * directly, which makes the dependency structural: redemption writes an approval record,
 * so invitations without the gate would have nowhere to put their decision. Setting
 * {@code invitations.enabled} without {@code approval.enabled} therefore wires nothing, in
 * the same way a mechanism with no registration installs no login.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "uniauth.approval.invitations", name = "enabled", havingValue = "true")
class InvitationConfiguration {

	private static final Logger LOGGER = LoggerFactory.getLogger(InvitationConfiguration.class);

	/**
	 * Fails the context on a path that could never work, rather than leaving every
	 * invitation to 404 with nothing anywhere saying why.
	 * @param properties the bound configuration
	 */
	InvitationConfiguration(UniAuthProperties properties) {
		properties.getApproval().getInvitations().validate();
	}

	/**
	 * Forgets everything on restart, so replace it in any deployment that cares.
	 *
	 * <p>
	 * It warns rather than refuses. Durability is the deployment's choice — the same
	 * bargain {@code InMemoryApprovalStore} strikes — but it has to be said out loud,
	 * because the failure is quiet: a console pointed at an in-memory store sees only the
	 * invitations created in its own process, which reads as a broken console rather than
	 * as the limitation it is.
	 * @param properties supplies the default expiry
	 * @return the in-memory store
	 */
	@Bean
	@ConditionalOnMissingBean
	InvitationStore uniAuthInvitationStore(UniAuthProperties properties) {
		LOGGER.warn("UniAuth is using InMemoryInvitationStore: invitations are lost on restart, "
				+ "are not shared between instances, and an admin console pointed at this store sees only "
				+ "the invitations created in its own process. Supply your own InvitationStore bean for anything "
				+ "beyond a demo.");
		return new InMemoryInvitationStore(Clock.systemUTC(),
				properties.getApproval().getInvitations().getDefaultExpiry());
	}

	@Bean
	@ConditionalOnMissingBean
	InvitationRedemption uniAuthInvitationRedemption(InvitationStore invitations, ApprovalStore approvals,
			ApplicationEventPublisher events, UniAuthProperties properties) {
		return new InvitationRedemption(invitations, approvals, events, properties);
	}

	/**
	 * Registered as a bean rather than component-scanned, like every other controller
	 * here, so {@code uniauth.enabled=false} genuinely backs off.
	 * @param store where invitations are looked up
	 * @param properties supplies the chooser and success paths
	 * @return the controller
	 */
	@Bean
	@ConditionalOnMissingBean
	UniAuthInvitationController uniAuthInvitationController(InvitationStore store, UniAuthProperties properties) {
		return new UniAuthInvitationController(store, properties, Clock.systemUTC());
	}

}
```

- [ ] **Step 4: Import it and pass the collaborator through**

In `ApprovalConfiguration.java`, add to the class annotations:

```java
@Import(InvitationConfiguration.class)
```

with `import org.springframework.context.annotation.Import;`, and change the manager bean to take the collaborator when one exists:

```java
	@Bean
	@ConditionalOnMissingBean
	ApprovalAuthorizationManager uniAuthApprovalAuthorizationManager(ApprovalStore store, MechanismResolver resolver,
			UniAuthProperties properties, ObjectProvider<InvitationRedemption> redemption) {
		// Absent unless invitations are on, in which case the gate is exactly what it was
		// before they existed.
		return new ApprovalAuthorizationManager(store, resolver, properties, redemption.getIfAvailable());
	}
```

with `import org.springframework.beans.factory.ObjectProvider;` and `import org.alexmond.uniauth.invitation.InvitationRedemption;`.

- [ ] **Step 5: Permit the invitation path on the chain**

In `UniAuthAutoConfiguration.uniAuthSecurityFilterChain`, extend the block that already permits the pending page:

```java
		ApprovalAuthorizationManager approval = approvalManager.getIfAvailable();
		if (approval != null) {
			// The waiting page has to be reachable by the very people the gate is keeping
			// out, or the redirect loops.
			permitted.add(properties.getApproval().getPendingPage());
			if (properties.getApproval().getInvitations().isEnabled()) {
				// An invitation has to work before anybody has logged in — that is the
				// entire point of it.
				permitted.add(properties.getApproval().getInvitations().getPath());
			}
		}
```

Add a line to the javadoc of `@param approvalManager` is not needed; the existing text still holds.

- [ ] **Step 6: Format, then run it and watch it pass**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/mvnw -q -f /home/alexm/IdeaProjects/uniauth/pom.xml spring-javaformat:apply
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh InvitationConfigurationTest
```

Expected: PASS, 7 tests.

- [ ] **Step 7: Write the end-to-end test and watch it fail**

Create `UniAuthInvitationTest.java` — the spec's test list, driven through the real filter chain, because the point is that redemption happens in the authorization path rather than in a handler. The internal store authenticates, since the mechanism is irrelevant to redemption and it keeps the test fast.

```java
package org.alexmond.uniauth;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationRedeemedEvent;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Invitations, end to end through the real filter chain.
 *
 * <p>
 * Driven this way because the claim happens in the authorization path and not in a success
 * handler: a test that stubbed the manager would prove nothing about the thing most likely
 * to be wrong. The internal store authenticates, since the mechanism is irrelevant to
 * redemption — the token is the proof, which is the whole reason this works the same for
 * SAML and LDAP as for OIDC.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.approval.enabled=true",
		"uniauth.approval.require-for=INTERNAL", "uniauth.approval.pending-page=/pending",
		"uniauth.approval.default-roles=USER", "uniauth.approval.invitations.enabled=true",
		"uniauth.internal.enabled=true", "uniauth.internal.users[0].username=jane",
		"uniauth.internal.users[0].password={noop}s3cret", "uniauth.internal.users[1].username=bob",
		"uniauth.internal.users[1].password={noop}s3cret" })
class UniAuthInvitationTest {

	private static final ApprovalKey JANE = new ApprovalKey("internal", "jane");

	private static final ApprovalKey BOB = new ApprovalKey("internal", "bob");

	@Autowired
	MockMvc mockMvc;

	@Autowired
	InvitationStore invitations;

	@Autowired
	ApprovalStore approvals;

	@Autowired
	Linker linker;

	@BeforeEach
	void forgetEverything() {
		this.approvals.remove(JANE);
		this.approvals.remove(BOB);
		this.linker.linked.clear();
		this.linker.refuse = false;
	}

	@Test
	void anInvitedPrincipalIsAdmittedOnTheFirstRequestWithNoPendingStep() {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");

		HttpSession session = openAndSignIn(invitation, "jane");

		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get()
			.extracting(ApprovalRecord::decidedBy)
			.isEqualTo("invitation:jane-record");
		assertThat(session).isNotNull();
	}

	@Test
	void theInvitationPathIsReachableBeforeAnybodyHasLoggedIn() throws Exception {
		// If it were not permitted, the gate would redirect it to the chooser and the
		// token would never be stashed — the invitation would silently do nothing.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		this.mockMvc.perform(get("/invite/" + invitation.token().value())).andExpect(redirectedUrl("/login"));
	}

	@Test
	void theRolesOnTheInvitationReachThePrincipal() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");
		HttpSession session = openAndSignIn(invitation, "jane");

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());

		assertThat(this.approvals.find(JANE)).get().extracting(ApprovalRecord::roles).isEqualTo(List.of("FAMILY"));
	}

	@Test
	void anInvitationWithNoRolesFallsBackToTheConfiguredDefault() {
		// Without this an admitted principal is refused by every hasRole() rule, which is
		// the bug #5 fixed arriving by a new route.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		openAndSignIn(invitation, "jane");

		assertThat(this.approvals.find(JANE)).get().extracting(ApprovalRecord::roles).isEqualTo(List.of("USER"));
	}

	@Test
	void theApplicationIsToldWhichLoginToLinkToWhichRecord() {
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		openAndSignIn(invitation, "jane");

		assertThat(this.linker.linked).singleElement().satisfies((event) -> {
			assertThat(event.key()).isEqualTo(JANE);
			assertThat(event.subjectRef()).isEqualTo("jane-record");
		});
	}

	@Test
	void theLinkSurvivesWithoutAnyListenerAtAll() {
		// Invitation.usedBy is why ApprovalRecord does not need a subjectRef field —
		// widening it would break every ApprovalStore implementor, as #5 already did once.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		openAndSignIn(invitation, "jane");

		assertThat(this.invitations.find(invitation.token())).get().satisfies((claimed) -> {
			assertThat(claimed.usedBy()).isEqualTo(JANE);
			assertThat(claimed.subjectRef()).isEqualTo("jane-record");
		});
	}

	@Test
	void aSecondPersonCannotClaimTheSameInvitationAndIsHeldByTheOrdinaryGate() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		openAndSignIn(invitation, "jane");

		HttpSession bobs = openAndSignIn(invitation, "bob");

		this.mockMvc.perform(get("/").session((MockHttpSession) bobs)).andExpect(redirectedUrl("/pending"));
		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.PENDING);
	}

	@Test
	void anExpiredInvitationIsRefusedAndAFreshOneForTheSameRecordWorks() throws Exception {
		Invitation stale = this.invitations.create("jane-record", Duration.ofMillis(1), List.of(), "admin");
		Thread.sleep(5);

		this.mockMvc.perform(get("/invite/" + stale.token().value()))
			.andExpect(redirectedUrl("/login?invite=expired"));

		// Re-inviting mints a new invitation. The dead one stays dead: a used or expired
		// token is never reopened.
		Invitation fresh = this.invitations.create("jane-record", null, List.of(), "admin");
		openAndSignIn(fresh, "jane");
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void aRevokedInvitationIsRefused() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		this.invitations.revoke(invitation.token(), "admin");

		this.mockMvc.perform(get("/invite/" + invitation.token().value()))
			.andExpect(redirectedUrl("/login?invite=revoked"));
	}

	@Test
	void anUnusableTokenRedirectsToAPageTheStarterActuallyServes() throws Exception {
		// The regression guard for #11's shape. A redirect to an unserved page is how a
		// consumer got ERR_TOO_MANY_REDIRECTS.
		this.mockMvc.perform(get("/invite/nonsense")).andExpect(redirectedUrl("/login?invite=unknown"));

		this.mockMvc.perform(get("/login").param("invite", "unknown")).andExpect(status().isOk());
	}

	@Test
	void theInvitationRedirectCarriesTheContextPath() throws Exception {
		// Review Focus 5. An application mounted under a context path would otherwise send
		// its visitors outside itself.
		this.mockMvc.perform(get("/app/invite/nonsense").contextPath("/app"))
			.andExpect(redirectedUrl("/app/login?invite=unknown"));
	}

	@Test
	void anAuthenticatedVisitorIsAdmittedOnlyAfterConfirming() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		HttpSession session = signIn("bob");
		// Bob is held by the ordinary gate at this point.
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));

		this.mockMvc
			.perform(get("/invite/" + invitation.token().value()).session((MockHttpSession) session))
			.andExpect(status().isOk());
		// Still not claimed: looking is not accepting.
		assertThat(this.invitations.find(invitation.token())).get()
			.satisfies((found) -> assertThat(found.usedBy()).isNull());

		this.mockMvc
			.perform(post("/invite/" + invitation.token().value()).session((MockHttpSession) session).with(csrf()))
			.andExpect(redirectedUrl("/"));
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());

		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.invitations.find(invitation.token())).get()
			.satisfies((found) -> assertThat(found.usedBy()).isEqualTo(BOB));
	}

	@Test
	void aListenerThatRefusesLeavesThePrincipalUnadmittedAndTheNextRequestRetries() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");
		this.linker.refuse = true;

		HttpSession session = openAndSignIn(invitation, "jane");

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.PENDING);

		// Admitted-but-unlinked would be worse than this; and because the claim is keyed
		// to Jane, recovery is just the next request.
		this.linker.refuse = false;
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	/** Signs in through the chooser after opening the invitation, as a person would. */
	private HttpSession openAndSignIn(Invitation invitation, String username) {
		try {
			HttpSession session = this.mockMvc.perform(get("/invite/" + invitation.token().value()))
				.andExpect(redirectedUrl("/login"))
				.andReturn()
				.getRequest()
				.getSession();
			HttpSession afterLogin = this.mockMvc
				.perform(formLogin("/login").user(username).password("s3cret").session((MockHttpSession) session))
				.andExpect(authenticated().withUsername(username))
				.andReturn()
				.getRequest()
				.getSession();
			this.mockMvc.perform(get("/").session((MockHttpSession) afterLogin));
			return afterLogin;
		}
		catch (Exception failed) {
			throw new IllegalStateException(failed);
		}
	}

	private HttpSession signIn(String username) throws Exception {
		return this.mockMvc.perform(formLogin("/login").user(username).password("s3cret"))
			.andExpect(authenticated().withUsername(username))
			.andReturn()
			.getRequest()
			.getSession();
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class Links {

		@Bean
		Linker linker() {
			return new Linker();
		}

	}

	/** Stands in for the application doing the linking. */
	static class Linker {

		final List<InvitationRedeemedEvent> linked = new ArrayList<>();

		volatile boolean refuse;

		@EventListener
		void onRedeemed(InvitationRedeemedEvent event) {
			if (this.refuse) {
				throw new IllegalStateException("the application's database was down");
			}
			this.linked.add(event);
		}

	}

}
```

Add `@Import(UniAuthInvitationTest.Links.class)` beside the other class-level annotations, with `import org.springframework.context.annotation.Import;`.

`invite-only` needs its own property set, so it needs its own class. Create
`UniAuthInviteOnlyTest.java`:

```java
package org.alexmond.uniauth;

import java.util.List;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code invite-only}, through the chain.
 *
 * <p>
 * Its own class because it needs its own property set — and because the assertion that
 * matters is about the <em>response</em>, not the record: a held principal gets a redirect
 * to the waiting page and a refused one gets 403, and only a real chain with
 * {@code PendingApprovalAccessDeniedHandler} on it can tell those apart.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.approval.enabled=true",
		"uniauth.approval.require-for=INTERNAL", "uniauth.approval.pending-page=/pending",
		"uniauth.approval.invitations.enabled=true", "uniauth.approval.invitations.invite-only=true",
		"uniauth.internal.enabled=true", "uniauth.internal.users[0].username=jane",
		"uniauth.internal.users[0].password={noop}s3cret", "uniauth.internal.users[1].username=bob",
		"uniauth.internal.users[1].password={noop}s3cret" })
class UniAuthInviteOnlyTest {

	private static final ApprovalKey JANE = new ApprovalKey("internal", "jane");

	private static final ApprovalKey BOB = new ApprovalKey("internal", "bob");

	@Autowired
	MockMvc mockMvc;

	@Autowired
	InvitationStore invitations;

	@Autowired
	ApprovalStore approvals;

	@BeforeEach
	void forgetEverything() {
		this.approvals.remove(JANE);
		this.approvals.remove(BOB);
	}

	@Test
	void anUninvitedPrincipalGetsAPlainRefusalRatherThanTheWaitingPage() throws Exception {
		HttpSession session = this.mockMvc.perform(formLogin("/login").user("bob").password("s3cret"))
			.andExpect(authenticated().withUsername("bob"))
			.andReturn()
			.getRequest()
			.getSession();

		// 403, not a redirect to /pending. Nobody is coming to approve them, and the
		// waiting page implies a queue somebody is reading.
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isForbidden());
		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.DENIED);
		assertThat(this.approvals.find(BOB)).get().extracting(ApprovalRecord::decidedBy).isEqualTo("invite-only");
	}

	@Test
	void anInvitedPrincipalIsStillAdmitted() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");
		HttpSession session = this.mockMvc.perform(get("/invite/" + invitation.token().value()))
			.andExpect(redirectedUrl("/login"))
			.andReturn()
			.getRequest()
			.getSession();
		HttpSession afterLogin = this.mockMvc
			.perform(formLogin("/login").user("jane").password("s3cret").session((MockHttpSession) session))
			.andExpect(authenticated().withUsername("jane"))
			.andReturn()
			.getRequest()
			.getSession();

		this.mockMvc.perform(get("/").session((MockHttpSession) afterLogin)).andExpect(status().isOk());

		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void theChooserStaysReachableSoARefusedPersonCanSignOutAndTryTheRightLink() throws Exception {
		this.mockMvc.perform(get("/login")).andExpect(status().isOk());
	}

}
```

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-test.sh 'UniAuthInvitationTest,UniAuthInviteOnlyTest'
```

Expected: these pass once Steps 3–5 are in. If `theInvitationPathIsReachableBeforeAnybodyHasLoggedIn` fails with a redirect to `/login` *without* the token having been stashed, the permit in Step 5 is missing or the path pattern does not match.

- [ ] **Step 8: Run the whole reactor**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
/home/alexm/IdeaProjects/uniauth/scripts/dev-verify.sh
```

Expected: green — tests, spring-javaformat, Checkstyle, PMD, and JaCoCo ≥ 80%. Green here is green in CI. If JaCoCo is short, the gap will be in the branches of `Invitation.status` or the controller's reason mapping; add the missing case to the owning task's test rather than lowering the gate.

- [ ] **Step 9: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add uniauth-spring-boot-starter/src
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
feat(invitations): wire it up, permit the path, warn about the default store (#29)

InvitationConfiguration is imported from ApprovalConfiguration, which makes
the dependency structural rather than documented: redemption writes an
approval record, so invitations without the gate would have nowhere to put
their decision.

The invitation path joins the permitted list beside the pending page. It has
to work before anybody has logged in — that is the entire point of it — and
without the permit the gate would redirect it to the chooser and the token
would never be stashed, so the invitation would silently do nothing.

The in-memory store warns rather than refuses: durability is the
deployment's choice, the same bargain InMemoryApprovalStore strikes. But it
says so, because the failure is quiet — a console pointed at an in-memory
store sees only its own process's invitations, which reads as a broken
console.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

### Task 8: Documentation

**Files:**
- Create: `docs/modules/ROOT/pages/invitations.adoc`
- Modify: `docs/modules/ROOT/nav.adoc` — the entry, after the approval gate
- Modify: `docs/modules/ROOT/pages/configuration.adoc` — the property table rows
- Modify: `docs/modules/ROOT/pages/approval.adoc` — a cross-reference
- Modify: `CHANGELOG.adoc` — the unreleased section
- Modify: `CLAUDE.md` — the approval-gate section and the extension-points list

**Interfaces:** none. This task ships the prose; the code is done.

**Why this is its own task.** The docs are version-bound text that freezes into the release tag — `release-prep` Step 2 exists because a feature shipped with no page, or with prose describing the old behaviour, cannot be fixed without re-releasing. A reviewer can reject the prose while accepting the code.

- [ ] **Step 1: Write `invitations.adoc`**

```adoc
= Invitations
:description: Admitting a named person before their first login.

The approval gate answers "somebody logged in; do we let them in?". A stranger has to turn
up first, and somebody has to notice.

Invitations are the other order. The application already holds a record for Jane, with no
way to sign in; an invitation is a one-use URL that attaches whichever login she completes
to *that record*. This is account claiming, not user provisioning — the record exists, the
login does not.

[source,yaml]
----
uniauth:
  approval:
    enabled: true                 # <1>
    invitations:
      enabled: false
      path: /invite/{token}       # <2>
      default-expiry: 14d
      invite-only: false          # <3>
----
<1> Required. Redemption writes an approval record, so invitations without the gate have
    nowhere to put their decision — switching them on alone wires nothing.
<2> Must contain `{token}`. Validated at startup, because without it every invitation
    would 404 with nothing saying why. The starter permits this path on its chain: an
    invitation has to work before anybody has logged in.
<3> With this on, an uninvited principal is refused outright — a plain 403 rather than the
    waiting page. Telling somebody who will never be admitted to keep waiting is a lie.

== The flow

. An administrator calls `InvitationStore.create(subjectRef, ttl, roles, createdBy)` and
  gets back an `Invitation` carrying its token.
. They deliver the URL however they like. Sending it is out of scope — the application or a
  person does that.
. Jane opens it. The token goes on her session and she lands on the chooser.
. She signs in with Google, or the directory, or anything else enabled. An ordinary round
  trip.
. Her first authenticated request passes through `ApprovalAuthorizationManager`, which
  claims the invitation, publishes `InvitationRedeemedEvent`, and records her as
  `APPROVED`.
. The application's listener links `(google, sub)` to Jane's record.

She never sees a waiting page.

== Why a token and not an email address

Matching on the invited address drags in `email_verified`, Gmail dots and plus-tags, case
folding, "the same address from another provider must not be admitted", and a
non-disclosure rule so an uninvited login cannot reveal whether an address is invited.

A token removes all of it. The token *is* the proof, so there is nothing to normalise and no
verified-claim problem — which is also why this works identically for SAML and LDAP, where
email matching could not: `PrincipalIdentity.emailVerified` is a nullable `Boolean` precisely
because SAML carries no equivalent and GitHub may report no address at all. Disclosure stops
mattering too: whoever holds the token already holds the invitation, so telling them it has
expired is a service rather than a leak.

The cost is that the invitation has to survive the redirect out to the provider and back. It
rides the session, because the alternatives are per-mechanism — OAuth2 `state`, SAML
`RelayState`, form login neither — and three implementations of one idea is the split the
single chain exists to avoid.

== The URL is the credential

Whoever holds the link gets the record it names. That is inherent to link invitations and no
design removes it.

What the starter does is make it deliberate. An *authenticated* visitor to an open
invitation gets a confirmation page — "you are signed in as bob@example.com; accept as
bob@example.com?" — and nothing is claimed until they post it. A mis-sent link opened by the
wrong colleague is then a decision somebody made rather than something that happened.

That page is also the recovery path when a session is lost mid-login, which happens: sessions
are in memory, which is why the deployments are `Recreate`. The invitation is still
unclaimed, so reopening the URL claims it without a second sign-in.

== One use means one person, not one request

`InvitationStore.redeem` is keyed by principal. Claiming again with the *same* key succeeds
and is a no-op; claiming with a different one fails.

This matters because of what happens when the application's listener throws. The event is
published synchronously inside the authorization decision and *a listener that throws fails
the admission* — the principal stays pending and the request is refused. Admitted-but-unlinked
would be worse: the person would be browsing as nobody, holding a session no record backs.

If the claim made the token dead, one transient failure would strand Jane with a URL that can
never work again. Instead her next request redeems as a no-op and she is admitted the moment
the application recovers. The risk one-use actually guards against is a *second person*
claiming the record, and that is exactly what it still guards against.

== Linking, with or without a listener

[source,java]
----
@EventListener
void onRedeemed(InvitationRedeemedEvent event) {
    people.linkLogin(event.subjectRef(), event.key());   // (google, sub) -> Jane
}
----

The link is durable without any listener at all: `Invitation.usedBy` records which
`ApprovalKey` claimed which `subjectRef`, permanently, so the mapping is recoverable by
querying the store. That is why `ApprovalRecord` gains no `subjectRef` field — widening it
would break every `ApprovalStore` implementation, which it already did once.

== Roles

An invitation carries roles, and falls back to `uniauth.approval.default-roles` when it names
none.

This is not optional detail. A federated principal arrives with `OIDC_USER` and `SCOPE_*` and
no `ROLE_` at all, so an approval granting nothing admits somebody who is then refused by
every `hasRole()` rule in the application — a working sign-in that reaches nothing, which
reads as a broken application rather than as a permissions decision.

== Any provider may redeem

An invitation names *who* may come in, not *how* they must authenticate, so it carries no
provider field. The gate's keys are `(provider, principal)`, so the resulting approval is
scoped to whichever provider answered. A deployment that later needs an invitation pinned to
one provider gets an optional field, not a redesign.

== When a link does not work

An unusable token redirects to the chooser with a reason — `?invite=unknown`, `used`,
`expired` or `revoked` — which the login template renders as one line.

Deliberately not a page of its own. The starter once redirected to a page it did not serve
and a consumer got `ERR_TOO_MANY_REDIRECTS`; an `outcome-page` property would be that mistake
with a new name. The chooser already exists and is already served.

== The store

`InvitationStore` is an SPI, on the same bargain as `ApprovalStore`: UniAuth owns the flow and
never the table. `InMemoryInvitationStore` is the default so the flow works out of the box,
and it is *not production-fit* — invitations are lost on restart, nothing is shared between
instances, and an admin console pointed at it sees only the invitations created in its own
process. The starter says so once at startup rather than refusing to run, because durability
is the deployment's choice.

One method carries a contract an implementation can break silently:

TIP: `redeem` must be a compare-and-set, not a read-then-write. A read-then-write passes
every single-threaded test and admits two people under load.

Unlike `ApprovalStore`, this interface can enumerate from the start. An administrator cannot
manage invitations they cannot list.
```

- [ ] **Step 2: Add the nav entry**

In `docs/modules/ROOT/nav.adoc`, after the approval gate line:

```adoc
* xref:invitations.adoc[Invitations]
```

- [ ] **Step 3: Add the property rows**

In `configuration.adoc`, inside the `== Approval gate` table after the `default-roles` row:

```adoc
| `uniauth.approval.invitations.enabled` | `false` | Admitting a named person before their first login. Needs `uniauth.approval.enabled`.
| `uniauth.approval.invitations.path` | `/invite/{token}` | Where an invitation is redeemed. Must contain `{token}`; validated at startup. Permitted on the chain, since it has to work before anybody has logged in.
| `uniauth.approval.invitations.default-expiry` | `14d` | How long an invitation lasts when its creator names no ttl.
| `uniauth.approval.invitations.invite-only` | `false` | Refuse an uninvited principal outright — a plain 403 rather than the waiting page.
```

and extend the sentence after the table:

```adoc
See xref:invitations.adoc[invitations] for the `InvitationStore` SPI and the linking event.
```

- [ ] **Step 4: Cross-reference from the approval page**

At the end of `approval.adoc`'s opening section, after "Approving admits them on their next
request — no second sign-in.", add:

```adoc
The gate assumes a stranger arrives first. For the other order — the application already
holds a record for somebody and wants to hand them a way to claim it — see
xref:invitations.adoc[invitations].
```

- [ ] **Step 5: Add the changelog entry**

At the top of `CHANGELOG.adoc`, below `= Changelog` and above `== 4.1.1.1`:

```adoc
== Unreleased

* *New — invitations* (#29), `uniauth.approval.invitations.enabled`. The approval gate needs a
  stranger to turn up first. Invitations are the other order: the application already holds a
  record for somebody, and a one-use URL attaches whichever login they complete to that
  record. A token rather than a matched email address, which removes `email_verified`, address
  normalisation, cross-provider matching and the whole disclosure question — and makes SAML and
  LDAP work as well as OIDC. Redemption happens in `ApprovalAuthorizationManager`, the one
  place every request passes exactly once, so one implementation covers all four mechanisms.
  `InvitationRedeemedEvent` is the linking contract and a listener that throws fails the
  admission, because admitted-but-unlinked is worse than "try again"; one-use is keyed by
  principal so that failure can be retried rather than stranding the invited person.
  `invite-only` refuses an uninvited principal outright instead of telling somebody who will
  never be admitted to keep waiting.
```

- [ ] **Step 6: Record what the next session needs to know**

In `CLAUDE.md`, at the end of the `### Approval gate` section, add:

```markdown
#### Invitations claim an account, they do not provision one

`uniauth.approval.invitations.enabled` hands a named person a one-use URL that attaches
whichever login they complete to a record the application already holds. The issue (#29)
proposed matching on the invited email address; the token in the URL replaces that, and
deletes `email_verified`, address normalisation, cross-provider matching and the disclosure
rule along with it — which is also why it works for SAML and LDAP, where email matching
could not.

Four things that will bite if changed carelessly:

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

`Invitation.usedBy` is why `ApprovalRecord` does not gain a `subjectRef` field: the link is
already durable, and widening that record would break every `ApprovalStore` implementor, as
#5 did once.
```

and in the extension-points list, after the `UniAuthBasicEntryPoint` entry:

```markdown
- An **`InvitationStore`** bean — the invitation table, like `ApprovalStore` is the approval
  one. Unlike it, this SPI can enumerate from the start (#10 is a real gap, but a sibling
  does not inherit it). An **`InvitationRedeemedEvent`** listener is how an application links
  the admitted login to its own record; it may refuse by throwing, which leaves the principal
  pending.
```

- [ ] **Step 7: Check for leaks and verify the docs build**

```bash
export JAVA_HOME=$HOME/.jdks/temurin-21
~/.claude/skills/lab-leak-guard/lab-scan.sh
grep -rn 'TODO\|TBD\|FIXME' /home/alexm/IdeaProjects/uniauth/docs/modules/ROOT/pages/invitations.adoc
```

Expected: the scan passes, and the grep finds nothing.

- [ ] **Step 8: Commit**

```bash
git -C /home/alexm/IdeaProjects/uniauth add docs CHANGELOG.adoc CLAUDE.md
git -C /home/alexm/IdeaProjects/uniauth commit -m "$(cat <<'MSG'
docs: invitations (#29)

A page of its own rather than a section on the approval gate: the two answer
opposite questions, and the gate's page would have to keep saying "unless an
invitation is in play".

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AUEMJh4nY3NuheerRW1At6
MSG
)"
```

---

## After the plan

Phase 1 is shippable on its own: an application can create invitations in code, hand out the
URLs, and link the logins. It has no invitation **UI** — that is phase 2 (the example webapp)
and phase 3 (the admin console), each with its own plan.

Two things to carry into the phase 2 plan:

- The approval queue UI lives in the **example webapp** (`ApprovalController` serves
  `/pending` and `/approvals`, `approvals.html` renders the list), not in `uniauth-admin`.
  That is where invitations are cheapest to prove, and it is also why #11 is precisely a
  *starter* gap.
- Re-inviting creates a **new** invitation for the same `subjectRef`. Invitations are never
  reopened, because a used token has to stay dead. The webapp's view needs a "re-invite"
  action, not an "extend" one.

The release carrying this work also wants `release-prep`, and the changelog section renamed
from `Unreleased` to its version.
