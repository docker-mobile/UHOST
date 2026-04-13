# Security Policy

This repository is an experimental hosting control plane and UVM stack. Treat it
as beta software and report security issues privately.

## Reporting

Do not open public GitHub issues for credential leaks, auth bypasses, runtime
isolation failures, or secret-disclosure bugs.

Instead, contact the maintainer through GitHub security reporting or direct
maintainer channels and include:

- affected component and version or commit
- exact reproduction steps
- expected versus actual security boundary
- whether the issue affects same-host beta deployments only or broader surfaces

## Scope

High-priority reports include:

- authentication and authorization bypasses
- secrets exposure or routed secret reveal failures
- policy / governance enforcement bypasses
- UVM isolation or guest boundary escapes
- supply-chain or provenance verification bypasses

## Expectations

The repository aims for secure-by-default platform behavior, but it is still a
beta system. Some areas are intentionally same-host and experimental; reports
should still be made so the boundary can be tightened rather than implied.
