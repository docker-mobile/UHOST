## Summary

- explain the user-visible or operator-visible change
- call out contract, state, or runtime surface changes explicitly

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] focused runtime or evidence checks, if applicable

## Risk

- list the main failure mode
- list rollback or containment steps if the change is operational
