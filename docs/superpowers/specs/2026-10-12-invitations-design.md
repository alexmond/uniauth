# Invitations — admit a named person before their first login

Design for [#29](https://github.com/alexmond/uniauth/issues/29). Supersedes the
email-matching shape the issue proposes; see *What changed from the issue* at the end.

## The problem

The approval gate answers "somebody logged in; do we let them in?". A stranger has to
arrive first, and an administrator has to notice and decide.

Some applications want the other order. An application already holds a record for a
person — "Jane", with no way to sign in — and wants to hand Jane a way to attach a
federated login to *that record*. This is **account claiming**, not user provisioning:
the record exists, the login does not, and the invitation is the one-time bridge that
says whoever completes this login is Jane.

The motivating case: a private application admitting a handful of family members with
their Google accounts, each tied to a record the application already holds.

## The flow

```
admin         InvitationStore.create(subjectRef, ttl, roles)  ->  token + URL
              sends the URL however they like (email, copy-paste, SMS)

person        GET /invite/{token}        validate, stash in session, go to chooser
person        signs in with Google      ordinary OAuth round trip
first request ApprovalAuthorizationManager sees the stashed token
              -> redeem (one-use), write APPROVED, publish the event
application   links (google, sub) to Jane's record
person        browses as Jane
```

### Why the token, and not the email address

The issue matches on email address. That drags in `email_verified`, Gmail dots and
plus-tags, case folding, "the same address from another provider must not be admitted",
and a non-disclosure rule so an uninvited login cannot reveal whether an address is
invited.

**A token in the URL removes all of it.** The token *is* the proof, so there is no
address to normalise and no verified-claim problem — which also means SAML and LDAP work
exactly as well as OIDC, where email matching could not: `PrincipalIdentity.emailVerified`
is a nullable `Boolean` precisely because SAML carries no `email_verified` equivalent and
GitHub may report no address at all. Disclosure stops mattering too: whoever holds the
token already holds the invitation, so telling them it has expired is a service, not a
leak.

The cost is that the invitation must survive the redirect to the provider and back. That
is the one genuinely new problem, and it is addressed under *Session loss and the
already-signed-in case*.

### Binding to the stable key is free

`ApprovalKey.of()` uses `authentication.getName()`, which for OIDC is `sub`. Approval
records are therefore already keyed by subject and never by email. The invitation is a
token lookup; the record it writes is keyed by `sub`. The issue's "bind to the stable key
at first use" requirement needs no work at all.

## Components

### `InvitationStore` — the SPI

Mirrors `ApprovalStore`'s bargain: the library owns the flow, never the table. Owning a
table would force Spring Data, a schema and migrations onto every consumer.

```java
public record Invitation(InvitationToken token, String subjectRef, List<String> roles,
        Instant createdAt, String createdBy, Instant expiresAt,
        Instant usedAt, ApprovalKey usedBy, Instant revokedAt) {

    InvitationStatus status(Instant now);   // OPEN | USED | EXPIRED | REVOKED
}

public interface InvitationStore {

    Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy);

    Optional<Invitation> find(InvitationToken token);

    /**
     * Atomically claims an OPEN invitation for this principal. The one and only place
     * one-use is enforced. Claiming again with the SAME key succeeds and is a no-op;
     * claiming with a different key fails.
     */
    Invitation redeem(InvitationToken token, ApprovalKey admitted);

    void revoke(InvitationToken token, String revokedBy);

    List<Invitation> list(InvitationStatus... statuses);
}
```

`redeem` is the only place one-use is enforced, and the SPI contract requires it to be
atomic — a compare-and-set, not a read-then-write. Two simultaneous logins must not both
claim Jane. This is the one thing an implementor can get wrong silently, so it is stated
on the method rather than left to be inferred.

`list` exists from the start, which is why **#10 is not a prerequisite for this work**.
`ApprovalStore`'s inability to enumerate anything but `pending()` is a real gap, but a
sibling SPI does not inherit it.

### `InvitationToken`

Opaque, URL-safe, generated from a `SecureRandom` with at least 128 bits of entropy. It
is a bearer credential: whoever holds it can claim the record it names. It is never
derived from the `subjectRef`, and it is not a signed self-contained token — one-use and
revocation require a store lookup anyway, so statelessness would buy nothing while
reintroducing the per-mechanism split (OAuth2 `state` versus SAML `RelayState`) that the
single chain exists to avoid.

### `InMemoryInvitationStore` — the default, and a warning

Supplied so the flow works out of the box, and **not production-fit**. Durability is the
deployment's choice, so the starter warns rather than refuses — the same bargain
`InMemoryApprovalStore` already strikes. One line at startup when it is in use, saying
that invitations are lost on restart, and that a console pointed at an in-memory store
sees only the invitations created in its own process.

### `InvitationController` — the endpoint

At a configurable path, default `/invite/{token}`, which must contain `{token}`.
Permitted, like the pending page — it has to work before anyone has logged in.

`GET` with an **anonymous** caller and an OPEN invitation: stash the token in the session,
redirect to the chooser.

`GET` with an **anonymous** caller and a token that is not OPEN: redirect to the chooser
with `?invite=expired|used|unknown`, which `login.html` renders as one line.

> **No new page, deliberately.** #11 happened because the starter redirected to a page it
> never served, and the consumer got `ERR_TOO_MANY_REDIRECTS`. An `outcome-page` property
> would be the same mistake with a new name. The chooser already exists and is already
> served, so the outcome goes there.

`GET` with an **authenticated** caller: a confirmation page — see below. `POST` redeems.

### Redemption, in the authorization manager

In `ApprovalAuthorizationManager`, where first sightings are already recorded, and for the
same reason CLAUDE.md gives for putting them there: *"Four mechanisms means four success
handlers; every request passes authorization exactly once."* Redeeming in the
authorization manager works for internal, LDAP, OAuth2 and SAML without four copies of
anything.

On an authenticated request whose status is `UNKNOWN`, when the session holds a token that
is still OPEN:

1. `redeem(token, key)` — atomic; if it fails, the invitation was claimed in the meantime
   and this principal falls through to the ordinary gate.
2. `recordPending(key, identity, mechanism)` then
   `decide(key, APPROVED, "invitation:" + id, roles)` — the record reads as if an
   administrator approved, with the invitation as the reason, which is what the audit
   trail needs.
3. Publish `InvitationRedeemedEvent`.
4. Clear the token from the session.

**Roles come from the invitation, falling back to `uniauth.approval.default-roles`.** The
issue says roles are out of scope, but they cannot be: #5 exists because a federated
principal arrives with `OIDC_USER` and `SCOPE_*` and no `ROLE_` at all, so an approval
granting nothing reproduces exactly the bug #5 fixed — admitted, then refused by every
`hasRole()` rule in the application.

### `invite-only`

`uniauth.approval.invitations.invite-only: true` makes an uninvited `UNKNOWN` principal
**`DENIED`** rather than `PENDING` — a plain 403 rather than the waiting page, which is
already what `ApprovalStatus.DENIED` means and what
`PendingApprovalAccessDeniedHandler` already distinguishes. Telling someone who will never
be admitted to keep waiting is a lie.

### `InvitationRedeemedEvent` — the linking contract

```java
public record InvitationRedeemedEvent(ApprovalKey key, String subjectRef,
        PrincipalIdentity identity, InvitationToken token) { }
```

Published **synchronously inside the authorization decision**, and **a listener that throws
fails the admission**: the principal is not approved and the request is refused.
Admitted-but-unlinked is worse than "try again" — the person would be browsing as nobody,
holding a session that no record backs. This is an unusual contract for a Spring event and
is stated in the javadoc.

**Retry is why `redeem` is keyed by principal and not merely by token.** A failed listener
leaves the invitation claimed; if that made the token dead, a transient failure in the
application would strand Jane with a URL that can never work and no way back except an
administrator noticing. Instead, re-claiming with the *same* `ApprovalKey` succeeds as a
no-op, so Jane's next request retries the event and is admitted once the application
recovers. One-use therefore means *one principal*, not one HTTP request — which is the
property that actually matters, since the risk being guarded against is a second person
claiming the record.

The link is **also durable without the event**. `Invitation.usedBy` records which
`ApprovalKey` claimed which `subjectRef`, permanently, so `(google, sub) -> Jane` is
recoverable by querying the invitation store. This is why `ApprovalRecord` does not gain a
`subjectRef` field: widening it would be breaking for every `ApprovalStore` implementor,
which #5 already did once.

## Session loss and the already-signed-in case

Two situations reach the same path.

**A pod restarted mid-OAuth.** Sessions are in memory, which is why deployments are
`Recreate`. The stashed token is gone, so the person returns authenticated and unlinked,
and lands as `PENDING`.

**Someone clicks a link while signed in as someone else.** Bob opens Jane's invitation
while signed in as Bob.

The second is not a flaw the design can remove: **the URL is the credential**, so whoever
holds it gets Jane's record. That is inherent to link invitations. What the design can do
is make it deliberate rather than accidental, so an authenticated visitor to an OPEN
invitation gets a confirmation step — *"you are signed in as bob@example.com; claim this
invitation as bob@example.com?"* — and redeems on `POST`.

That same page is the recovery path for the restart case: the invitation is still unused,
so reopening the URL claims it directly, without a second sign-in. Built deliberately
rather than discovered.

## Any provider may redeem

`Invitation` carries no provider field. An invitation names *who* may come in, not *how*
they must authenticate, and the gate's keys are `(provider, principal)` so the resulting
approval is scoped to whichever provider answered. If a deployment later needs an
invitation pinned to one provider, that is an added optional field, not a redesign.

## Configuration

```yaml
uniauth:
  approval:
    enabled: true
    invitations:
      enabled: false            # off by default, like every other mechanism here
      path: /invite/{token}     # must contain {token}
      default-expiry: 14d
      invite-only: false        # true: no invitation means 403, not the waiting page
```

## User interfaces

### Phase 2 — the example webapp

Invitations land beside the approval queue that already exists there:
`ApprovalController` serves `/pending` and `/approvals`, and `approvals.html` renders the
waiting list. The webapp is where the approval UI lives today, so it is where invitations
are cheapest to prove.

An **Invitations** view: create one for a `subjectRef`, see open, used, expired and
revoked, revoke, and re-invite an expired one. Re-inviting creates a *new* invitation for
the same `subjectRef`; invitations are never reopened, because a used token must stay
dead.

### Phase 3 — the admin console

`uniauth-admin` gains an **Invitations** page beside its stores list, and its user listing
gains a single **`access`** column rather than two:

```
—  ·  INVITED  ·  EXPIRED  ·  PENDING  ·  APPROVED  ·  DENIED
```

One column because it is one lifecycle, derived from the invitation store and the approval
store together.

**This does not breach the console's charter, given a durable store.** The console
administers populations that *"exist independently of any application and survive a
restart"*, and it stopped administering applications because their accounts lived in an
application's memory. A persisted invitation table is neither of those things: it survives
restarts, and the console and the application can both point at the same store without the
application publishing an admin API — which is the part that had no business in an
authentication library.

**The honest limitation.** Three key spaces have to be correlated:

| | keyed by |
|---|---|
| console user listing | username / DN |
| approval record | `(provider, sub)` |
| invitation | `subjectRef` |

`Invitation.usedBy` links invitation to approval once claimed. Neither links to a console
username unless a provider account's subject is its username — true at
`uniauth-authserver`, not true for LDAP or Google. **So the column is accurate for
provider accounts and blank for directory entries and federated logins the console has
never seen.** Blank, not "not invited": showing a definite negative for someone who was in
fact invited is worse than showing nothing.

## Testing

Driven through the real filter chain, because the point is that redemption happens in the
authorization path rather than in a handler. The internal store is used to authenticate,
since the mechanism is irrelevant to redemption and it keeps the test fast.

- An invited principal is admitted on first sighting with no pending step, and the record
  reads `APPROVED` with the invitation as approver.
- The roles on the invitation reach the principal; an invitation with none falls back to
  `uniauth.approval.default-roles`.
- A second redemption by a *different* principal is refused, and that principal is held
  by the ordinary gate; re-claiming with the same principal succeeds, so a failed listener
  can be retried rather than stranding the invited person.
- An expired invitation is refused; a fresh invitation for the same `subjectRef` works.
- A revoked invitation is refused.
- `invite-only: true` gives an uninvited principal 403, not a redirect to `/pending`.
- An authenticated visitor to an OPEN invitation gets the confirmation page, and is
  admitted only after the `POST`.
- A token that is unknown, used or expired redirects to the chooser with the matching
  `?invite=` reason, and the chooser serves it — a regression guard against #11's shape.
- A listener that throws leaves the principal unadmitted.
- `InMemoryInvitationStore` logs its warning once at startup.

## Phasing

1. **Starter** — `InvitationStore`, `Invitation`, `InvitationToken`,
   `InMemoryInvitationStore`, `InvitationController`, redemption in
   `ApprovalAuthorizationManager`, the event, properties, the `?invite=` line on
   `login.html`, docs.
2. **Example webapp** — the Invitations view beside the approval queue.
3. **Admin console** — the Invitations page and the `access` column.

Each phase ships on its own and is useful without the next.

## What changed from the issue

| Issue | This design | Why |
|---|---|---|
| Match a named email address | A token in a URL | Removes `email_verified`, address normalisation, cross-provider matching and the disclosure rule; works for SAML and LDAP, which email matching could not |
| Verified claim only | Not applicable | There is no claim to verify; the token is the proof |
| Bind to `sub` after first use | Already the case | `ApprovalKey` is already keyed by `authentication.getName()` |
| Roles out of scope | Invitation carries roles | An approval granting none reproduces the bug #5 fixed |
| Admin console lists invitations | Yes, phase 3, with a stated limitation | Legitimate given a durable store; the user listing cannot be accurate for every backend |
| Needs #10 first | No | A sibling SPI has `list` from the start |
| Sending the invitation email | Still out of scope | The application or a person delivers the URL |
