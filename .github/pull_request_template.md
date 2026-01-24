## Description

<!-- Provide a clear and concise description of your changes -->

## Type of Change

<!-- Mark the relevant option with an 'x' -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] Test improvement
- [ ] CI/CD improvement

## Related Issue

<!-- Link to related issue(s) -->
Fixes #(issue)
Related to #(issue)

## Changes Made

<!-- List the key changes made in this PR -->

- 
- 
- 

## Cardano Compatibility

<!-- For cryptographic changes -->

- [ ] Changes maintain 100% binary compatibility with cardano-node
- [ ] Test vectors from cardano-base pass
- [ ] Follows relevant CIP specifications
- [ ] N/A (not a cryptographic change)

## Testing

<!-- Describe the tests you ran and how to reproduce them -->

- [ ] Unit tests pass: `cargo test --all-features`
- [ ] Integration tests pass
- [ ] Golden tests pass (for crypto changes)
- [ ] Property tests pass (for crypto changes)
- [ ] Manual testing performed
- [ ] Benchmarks run (for performance changes)

### Test Commands

```bash
# Commands used to test this PR
cargo test --all-features
cargo clippy --all-targets --all-features
```

## Documentation

- [ ] Code is self-documenting with clear variable/function names
- [ ] Public APIs have rustdoc comments
- [ ] Complex logic has inline comments explaining the "why"
- [ ] README updated (if applicable)
- [ ] CHANGELOG.md updated
- [ ] Examples added/updated (if applicable)

## Checklist

<!-- Mark completed items with an 'x' -->

- [ ] My code follows the project's code style
- [ ] I have run `cargo fmt` on my changes
- [ ] I have run `cargo clippy` and resolved all warnings
- [ ] I have added tests that prove my fix/feature works
- [ ] All new and existing tests pass locally
- [ ] I have updated the documentation accordingly
- [ ] My changes generate no new warnings
- [ ] I have checked for breaking changes
- [ ] I have updated CHANGELOG.md

## Security Considerations

<!-- If applicable, describe any security implications -->

- [ ] No security implications
- [ ] Security review required
- [ ] Constant-time operations verified (for crypto code)
- [ ] Memory zeroization verified (for secret keys)

## Performance Impact

<!-- If applicable, describe any performance implications -->

- [ ] No performance impact
- [ ] Performance improved (include benchmark results)
- [ ] Performance decreased (include justification)
- [ ] Performance impact unknown (benchmarks needed)

### Benchmark Results

<!-- If performance is affected, include before/after benchmark results -->

```
Paste benchmark results here
```

## Additional Context

<!-- Add any other context about the PR here -->

## Screenshots

<!-- If applicable, add screenshots to help explain your changes -->

---

<!-- By submitting this PR, you agree that your contributions are licensed under MIT OR Apache-2.0 -->
