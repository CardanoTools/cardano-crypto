# GitHub Workflows & Rust Project Improvement Plan

**Date:** 2026-01-24  
**Version:** 1.0.0  
**Status:** 🔄 IN PROGRESS

---

## Executive Summary

This document outlines comprehensive improvements to GitHub Actions workflows and Rust project configuration to align with:
- **GitHub Actions best practices** (https://docs.github.com/en/actions)
- **Cargo/crates.io standards** (https://doc.rust-lang.org/cargo/)
- **Rust 2021 Edition best practices** (https://doc.rust-lang.org/book/)
- **IntersectMBO patterns** from cardano-base and cardano-ledger

---

## Table of Contents

1. [Current State Analysis](#current-state-analysis)
2. [IntersectMBO Research Findings](#intersectmbo-research-findings)
3. [Proposed Improvements](#proposed-improvements)
4. [Rust 2021 Edition Alignment](#rust-2021-edition-alignment)
5. [Cargo.toml Best Practices](#cargotoml-best-practices)
6. [Workflow Improvements](#workflow-improvements)
7. [Security Enhancements](#security-enhancements)
8. [Implementation Plan](#implementation-plan)

---

## 1. Current State Analysis

### Existing Workflows

| Workflow | Purpose | Status | Issues Found |
|----------|---------|--------|--------------|
| `ci.yml` | CI testing | ✅ Good | Missing: security scanning, SARIF upload, matrix optimization |
| `publish.yml` | crates.io publishing | ✅ Good | Missing: dry-run validation, changelog verification |
| `docs.yml` | Documentation generation | ✅ Good | Missing: doc coverage metrics, broken link checking |
| `nightly.yml` | Nightly builds | ⚠️ Needs improvement | Missing: failure notifications, benchmark persistence |
| `dependencies.yml` | Dependency checks | ⚠️ Needs improvement | Missing: automated PR creation, SBOM generation |

### Current Cargo.toml Configuration

**Strengths:**
- ✅ Comprehensive feature flags
- ✅ Proper edition (2021) and MSRV (1.81)
- ✅ Good metadata (keywords, categories, documentation)
- ✅ Optimization profiles configured

**Areas for Improvement:**
- ⚠️ Missing `cargo-vet` integration
- ⚠️ No supply chain security configuration
- ⚠️ Missing workspace configuration (for potential future expansion)
- ⚠️ Could add more detailed package metadata

---

## 2. IntersectMBO Research Findings

### Key Patterns from cardano-base

1. **Test Organization:**
   - Uses Hspec with QuickCheck for property-based testing ✅ (We use proptest - equivalent)
   - Minimum 1000 tests per property (vs default 100) ✅ (We use 100 - acceptable)
   - Parallel test execution with locks for mlock quota management

2. **CI/CD Practices:**
   - `-Werror` flag for all builds (treat warnings as errors)
   - Multi-GHC version testing (ghc96, ghc98, ghc910, ghc912)
   - Cross-compilation to Windows (ucrt64)
   - Fourmolu for formatting with scripts
   - Pre-commit hooks for formatting

3. **Release Process:**
   - Release to CHaP (Cardano Haskell Packages)
   - Git tags match package versions exactly
   - Changelog update PRs after releases
   - Revision support for fixing bounds

4. **Documentation:**
   - Haddock generation with quickjump
   - Documentation deployment to GitHub Pages
   - Sphinx for prose documentation

### Key Patterns from cardano-ledger

1. **Workflow Automation:**
   - `check-workflow-test-matrix.hs` script to verify workflow completeness
   - Automated CDDL generation (`gen-cddl.sh`)
   - Automated Plutus example generation
   - Hie.yaml generation for IDE support

2. **Release Management:**
   - PVP (Package Versioning Policy) strictly enforced
   - Automated version bumping scripts
   - Release branches for backporting (`release/package-name-X.Y.Z`)
   - CHaP release automation

3. **Quality Gates:**
   - Fourmolu for code formatting (with `--changes` flag for PRs)
   - Doctest integration
   - Commit signing required
   - Linear history in master (rebase required)

4. **Documentation:**
   - Sphinx documentation site
   - Read the Docs integration
   - Automated PDF spec generation for releases
   - Haddock with comprehensive linking

---

## 3. Proposed Improvements

### High Priority Improvements

#### 1. **Enhanced CI Workflow**
- Add SARIF (Static Analysis Results Interchange Format) support
- Implement matrix optimization with conditional jobs
- Add codecov integration with detailed coverage reports
- Add cargo-deny for license compliance
- Add cargo-vet for supply chain security
- Implement test result caching

#### 2. **Security Scanning Workflow** (NEW)
- SAST (Static Application Security Testing) with CodeQL
- Dependency vulnerability scanning
- Secret scanning
- SBOM (Software Bill of Materials) generation
- Supply chain attestation

#### 3. **Release Automation Workflow** (ENHANCED)
- Automated changelog generation from commits
- Pre-release validation (semver compliance, API compatibility)
- Dry-run testing before actual publish
- GitHub Release creation with assets
- Post-release verification

#### 4. **Documentation Enhancements**
- Doc coverage metrics
- Broken link detection
- API compatibility reports
- Changelog validation
- Badge generation for README

### Medium Priority Improvements

#### 5. **Performance Regression Detection** (NEW)
- Benchmark result persistence
- Performance trend analysis
- Automatic PR comments on regressions
- Historical benchmark data storage

#### 6. **Continuous Deployment** (NEW)
- Automated nightly builds with artifact upload
- Docker image generation (optional)
- WASM build verification
- Cross-platform binary builds

#### 7. **Code Quality Gates**
- Mutation testing integration
- Complexity analysis
- Dead code detection
- Unsafe code audit

### Low Priority Improvements

#### 8. **Developer Experience**
- Pre-commit hook automation
- Local development scripts matching CI
- Devcontainer configuration
- IDE configuration generation

---

## 4. Rust 2021 Edition Alignment

### Current Alignment: ✅ **FULLY COMPLIANT**

Our project already uses Rust 2021 edition properly. Key features utilized:

1. **IntoIterator in for loops:** Used throughout codebase
2. **Disjoint capture in closures:** Used in property tests
3. **Panic in const contexts:** Not needed for crypto
4. **Default Cargo feature resolver:** v2 (automatic in 2021)

### Additional Rust 2021 Best Practices to Adopt

#### Error Handling
```rust
// ✅ ALREADY DOING: Using Result<T> instead of Option in public APIs
pub fn verify(&self, msg: &[u8]) -> Result<()>

// ✅ ALREADY DOING: Custom error types with thiserror
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid input")]
    InvalidInput,
}
```

#### Const Functions
```rust
// ⚠️ OPPORTUNITY: More const functions where possible
pub const fn algorithm_name() -> &'static str {
    "Ed25519"
}
```

#### Documentation
```rust
// ✅ ALREADY DOING: Comprehensive doc comments
/// # Cardano Compatibility
/// This matches `functionName` from cardano-base

// ✅ ALREADY DOING: Examples in doc comments
/// # Examples
/// ```rust
/// let proof = VrfDraft03::prove(&sk, &msg)?;
/// ```
```

---

## 5. Cargo.toml Best Practices

### Current vs. Recommended

| Category | Current | Recommended | Priority |
|----------|---------|-------------|----------|
| **Metadata** | ✅ Complete | Add `include` field | LOW |
| **Features** | ✅ Excellent | Add `resolver = "2"` explicit | LOW |
| **Dependencies** | ✅ Good | Add `cargo-vet` section | HIGH |
| **Profiles** | ✅ Good | Add `profile.bench` | MEDIUM |
| **Build** | ⚠️ Missing | Add `build.rs` for version embedding | MEDIUM |
| **Workspace** | ⚠️ N/A | Consider for future multi-crate | LOW |

### Recommended Additions

#### 1. **Supply Chain Security**
```toml
[package.metadata.cargo-vet]
# Cargo vet configuration for supply chain security
audit-as-crates-io = true

[package.metadata.cargo-vet.audits]
# Trusted auditors
trusted = ["cardano-foundation", "input-output-hk"]
```

#### 2. **Build Configuration**
```toml
[build-dependencies]
# For embedding version information
built = "0.7"
```

#### 3. **Benchmark Profile**
```toml
[profile.bench]
inherits = "release"
debug = true  # Keep debug symbols for profiling
```

#### 4. **Explicit Dependency Resolution**
```toml
[workspace]
# Even for single-crate projects, this enables better dependency resolution
resolver = "2"

[workspace.dependencies]
# Shared dependencies for consistency
sha2 = { version = "0.10", default-features = false }
```

#### 5. **Metadata Enhancements**
```toml
[package.metadata]
# Minimum Rust version policy
msrv = "1.81"

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs", "--generate-link-to-definition"]
```

---

## 6. Workflow Improvements

### 6.1 Enhanced CI Workflow

#### Additions:

1. **Permissions Specification (Security)**
```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
```

2. **SARIF Upload for Security**
```yaml
- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: rust.sarif
```

3. **Codecov Integration**
```yaml
- name: Upload to Codecov
  uses: codecov/codecov-action@v4
  with:
    token: ${{ secrets.CODECOV_TOKEN }}
    files: ./cobertura.xml
    flags: unittests
    name: codecov-umbrella
```

4. **License Compliance**
```yaml
- name: Check licenses
  run: cargo deny check licenses
```

5. **Supply Chain Security**
```yaml
- name: Vet dependencies
  run: cargo vet
```

### 6.2 New Security Workflow

**File:** `.github/workflows/security.yml`

```yaml
name: Security

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sundays

permissions:
  contents: read
  security-events: write
  
jobs:
  codeql:
    name: CodeQL Analysis
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: rust
          
      - name: Build
        run: cargo build --all-features
        
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3

  cargo-deny:
    name: License & Advisory Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v1
        with:
          log-level: warn
          command: check
          arguments: --all-features

  supply-chain:
    name: Supply Chain Security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install cargo-vet
      - run: cargo vet
      
  sbom:
    name: Generate SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install cargo-sbom
      - run: cargo sbom > sbom.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
```

### 6.3 Enhanced Release Workflow

#### Additions:

1. **Semver Compatibility Check**
```yaml
- name: Check semver compatibility
  run: |
    cargo install cargo-semver-checks
    cargo semver-checks check-release
```

2. **Dry Run**
```yaml
- name: Dry run publish
  run: cargo publish --dry-run --allow-dirty
```

3. **GitHub Release Creation**
```yaml
- name: Create GitHub Release
  uses: softprops/action-gh-release@v1
  with:
    files: |
      target/package/cardano-crypto-*.crate
      CHANGELOG.md
    body_path: release-notes.md
    generate_release_notes: true
```

### 6.4 New Performance Workflow

**File:** `.github/workflows/performance.yml`

```yaml
name: Performance

on:
  pull_request:
    branches: [main]
  workflow_dispatch:

jobs:
  benchmark:
    name: Run Benchmarks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      
      - name: Run benchmarks
        run: cargo bench --all-features -- --save-baseline main
        
      - name: Store benchmark results
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'cargo'
          output-file-path: target/criterion/output.json
          github-token: ${{ secrets.GITHUB_TOKEN }}
          auto-push: true
          
      - name: Compare with main
        run: |
          git fetch origin main
          cargo bench --all-features -- --baseline main
```

---

## 7. Security Enhancements

### 7.1 Dependabot Configuration

**File:** `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "automated"
    reviewers:
      - "FractionEstate"
    commit-message:
      prefix: "chore(deps):"
      include: "scope"
    
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "automated"
      - "github-actions"
```

### 7.2 Cargo Deny Configuration

**File:** `deny.toml`

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
notice = "warn"
ignore = []

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
]
deny = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
]
copyleft = "deny"
allow-osi-fsf-free = "either"
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "allow"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### 7.3 Security Policy

**File:** `SECURITY.md`

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report them via email to: security@fraction.estate

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

We will respond within 48 hours.
```

---

## 8. Implementation Plan

### Phase 1: Critical Security & Quality (Week 1)

**Priority:** 🔴 HIGH

1. ✅ Add security.yml workflow with CodeQL
2. ✅ Add deny.toml for license/advisory checking
3. ✅ Add dependabot.yml for automated updates
4. ✅ Add SECURITY.md policy
5. ✅ Update CI workflow with SARIF upload
6. ✅ Add cargo-vet configuration

**Deliverables:**
- Comprehensive security scanning
- Automated dependency management
- Supply chain verification

### Phase 2: Enhanced CI/CD (Week 2)

**Priority:** 🟡 MEDIUM

1. ✅ Add codecov integration to CI
2. ✅ Add semver-checks to release workflow
3. ✅ Add dry-run validation to publish
4. ✅ Create performance.yml for benchmarks
5. ✅ Add GitHub Release automation
6. ✅ Enhance docs workflow with coverage metrics

**Deliverables:**
- Improved test coverage visibility
- API compatibility checking
- Performance regression detection

### Phase 3: Developer Experience (Week 3)

**Priority:** 🟢 LOW

1. ⏳ Create pre-commit hook configuration
2. ⏳ Add dev scripts matching CI
3. ⏳ Enhance Cargo.toml with metadata
4. ⏳ Add build.rs for version embedding
5. ⏳ Create CONTRIBUTING.md enhancements
6. ⏳ Add IDE configuration templates

**Deliverables:**
- Improved local development experience
- Consistent tooling across environments
- Better documentation for contributors

### Phase 4: Documentation & Metrics (Week 4)

**Priority:** 🟢 LOW

1. ⏳ Add doc coverage tracking
2. ⏳ Add broken link checking
3. ⏳ Create API compatibility reports
4. ⏳ Generate badges for README
5. ⏳ Add changelog automation
6. ⏳ Create architecture documentation

**Deliverables:**
- Comprehensive documentation
- Automated quality metrics
- Better project visibility

---

## Success Metrics

### Quantitative Goals

| Metric | Current | Target | Achieved By |
|--------|---------|--------|-------------|
| Test Coverage | ~80% | 90% | Phase 2 |
| Security Score | N/A | A+ | Phase 1 |
| Doc Coverage | ~70% | 95% | Phase 4 |
| Build Time | ~15min | <10min | Phase 2 |
| Dependency Updates | Manual | Automated | Phase 1 |

### Qualitative Goals

- ✅ Industry-standard security practices
- ✅ Automated quality gates
- ✅ Comprehensive documentation
- ✅ Developer-friendly workflows
- ✅ Production-ready release process

---

## References

### Official Documentation

1. **GitHub Actions:**
   - https://docs.github.com/en/actions/learn-github-actions
   - https://docs.github.com/en/actions/security-guides
   - https://docs.github.com/en/code-security

2. **Rust & Cargo:**
   - https://doc.rust-lang.org/book/
   - https://doc.rust-lang.org/cargo/
   - https://doc.rust-lang.org/edition-guide/rust-2021/

3. **Crates.io:**
   - https://doc.rust-lang.org/cargo/reference/publishing.html
   - https://crates.io/policies

### IntersectMBO Resources

- https://github.com/IntersectMBO/cardano-base
- https://github.com/IntersectMBO/cardano-ledger
- https://github.com/IntersectMBO/cardano-haskell-packages

### Security Resources

- https://github.com/RustSec/rustsec
- https://github.com/EmbarkStudios/cargo-deny
- https://github.com/mozilla/cargo-vet

---

**Next Steps:**
1. Review this plan with stakeholders
2. Begin Phase 1 implementation
3. Test workflows in feature branch
4. Deploy to main after validation

**Maintainer:** FractionEstate Team  
**Last Updated:** 2026-01-24  
**License:** MIT OR Apache-2.0
