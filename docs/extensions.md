# Extension and Compatibility Policy

This document defines the current extension surface and the rules for keeping
it stable enough for a beta release.

## Scope

The extension surface is intentionally narrow. It covers declared manifests,
event subscriptions, background task contracts, compatibility policy, and
deprecation notices. It does not imply a full external plugin marketplace or a
distributed extension runtime.

## Core Contracts

The stable contracts currently live in `uhost-core`:

- `PluginManifest`
- `EventSubscription`
- `BackgroundTaskContract`
- `CompatibilityPolicy`
- `DeprecationNotice`

These contracts are the compatibility boundary for extension-aware lifecycle
registration.

## Registration APIs

The lifecycle service currently exposes:

- `POST /lifecycle/plugins`
- `GET /lifecycle/event-subscriptions`
- `POST /lifecycle/event-subscriptions`
- `GET /lifecycle/background-tasks`
- `POST /lifecycle/background-tasks`
- `GET /lifecycle/compatibility-policy`

## Compatibility Rules

- Every plugin must declare `min_api_version` and `max_api_version`.
- Registration fails if the plugin range does not include the platform's
  current extension API version.
- The manifest's supported range must not fall entirely below the minimum
  supported platform version.
- Event topics should include explicit version suffixes such as
  `mail.message.*.v1`.

## Background Task Expectations

Background task contracts declare:

- a stable task identifier,
- a maximum runtime,
- a maximum concurrency.

That keeps the platform's scheduler and the extension author aligned on
operational limits instead of treating tasks as unbounded callbacks.

## Deprecation Policy

- Every deprecation must include replacement guidance.
- Every deprecation must declare a `removal_not_before` date.
- Removal requires at least one compatibility window with warnings before the
  contract disappears.

## Beta Guidance

- Keep extensions additive where possible.
- Prefer versioned topics and new fields over silent semantic redefinition.
- Treat lifecycle registration as durable control-plane state, not as a
  best-effort cache.
- Do not claim ecosystem stability wider than the contracts currently
  registered and published by the lifecycle service.

## Related Docs

- [Configuration Model](config/overview.md)
- [Dependency Ledger](dependency-ledger.md)
- [Threat Model](threat-model.md)
