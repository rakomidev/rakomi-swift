<!-- SPDX-License-Identifier: MIT -->

# Security policy — Rakomi Swift SDK

**This file is the security policy for the `RakomiSDK` Swift package.** Rather than write a second set
of terms, it **adopts the terms** — response targets, coordinated-disclosure conditions, safe harbor,
what to include in a report, how reports are tracked, and how reporter personal data is handled — of
the Rakomi security policy published at:

- <https://github.com/rakomidev/rakomi-js/blob/main/SECURITY.md>

> ⚠ **Read this before you follow that link.** That policy states its own scope as the Rakomi
> JavaScript-family packages published on npmjs.com, and **it does not name this package.** This file
> does not claim otherwise. It adopts that policy's *terms* and applies them here, so that one set of
> terms governs every Rakomi SDK and there is only one place where those terms can change. **If you
> are reporting a vulnerability in this package, this file is the one that applies to you**, and the
> terms it adopts are the ones we will hold ourselves to.

Where this file and the adopted terms could be read as differing, the adopted terms govern, except on
the two matters this file settles for itself below: **scope** and **the absence of any way to
withdraw a published version**.

## Reporting a vulnerability

Please do **not** open a public issue for a security report.

- **Email:** security@rakomi.com
- **Private vulnerability reporting:**
  <https://github.com/rakomidev/rakomi-js/security/advisories/new>

Reports about this package are welcome through either channel. Note that the private-reporting link
above belongs to the Rakomi JavaScript SDK repository; there is no separate private-reporting channel
for this package yet, so **email is the channel we can state without qualification.**

What to include in a report, how reports are tracked, how often you will hear from us, and how
reporter personal data is handled are as set out in the adopted terms.

## Scope

**In scope:** the `RakomiSDK` Swift package — its source, its published tagged releases, and the
authentication and credential-handling logic it performs on the device.

**Out of scope:** the Rakomi platform, and the Rakomi JavaScript-family SDKs (those are the subject of
the policy linked above, in its own right); third-party packages this SDK depends on — report those to
their maintainers, though we will raise our minimum versions when a dependency has a known critical
vulnerability affecting our users; and everything the adopted terms list as out of scope.

## Supported versions

**No version of `RakomiSDK` has been published at the time of writing**, so no support window is
running and none is stated here. This file applies from the first published version onward. **We do
not restate a support window we cannot yet date, and nothing here should be read as creating one.**

**While this package is on the `0.x` line, it carries no dated support window at all.** Per
**Semantic Versioning 2.0.0 §4**: *"Major version zero (0.y.z) is for initial development. Anything
MAY change at any time. The public API SHOULD NOT be considered stable."* This is the same posture
every other Rakomi SDK holds while on its own `0.x` line. A dated support commitment
attaches once this package reaches `1.0`, not before; once it does, its supported-version window is
published at the SDK-support discovery endpoint alongside every other Rakomi SDK's window, and its
end-of-life path is a **superseding tag** — this package is never withdrawn via any registry-specific
deprecation mechanism that does not apply to Swift Package Manager.

## A published version cannot be withdrawn

This is a property of the distribution channel, and we state it plainly because it changes what a
fix can look like.

**A Swift Package version is a tag in a source repository.** Deleting or moving a published tag is
technically possible, and we do not do it. Removing a tag breaks resolution for everyone who pinned
the version as documented, and it does not retract anything already fetched or already attested.

**The same holds on the other channel this SDK family publishes to.** pub.dev gives a publisher no
ability to remove a published version; retraction there is available within seven days of
publication and is not deletion — a retracted version stays listed and stays resolvable for anyone
whose lockfile already names it ([publishing packages](https://dart.dev/tools/pub/publishing)).
Removal is a moderator-reviewed exception for a mistaken publication, requested within 48 hours
([pub.dev policy](https://pub.dev/policy)).

**Consequence, and it is the operative sentence:** a defect in a published version is corrected by
publishing a fixed, higher version together with disclosure through the channels named above —
never by withdrawing the defective one. We treat this as a reason to be slower before a release, not
as a reason to be quieter after one.

## Manufacturer

**Legal entity:** CRE8EVE Sp. z o.o.
**Registered address:** Tulipanowa 4, 72-003 Dobra, Poland (EU)
**Security contact:** security@rakomi.com (role-based — no personal mailbox or phone is published)

> This is a repository security policy, not a `.well-known/security.txt` web endpoint. The links
> above are absolute on purpose: this package is published to its own repository, where a relative
> link to a policy in another repository would not resolve.
