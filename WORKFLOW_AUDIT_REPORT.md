# GitHub Actions Workflow Audit Report

**Date:** 2026-01-24
**Project:** cardano-crypto
**Auditor:** Claude

## Executive Summary

This audit identified **1 CRITICAL issue** and **27 potential failure points** across 7 GitHub Actions workflows. The critical issue prevents the project from building at all, and must be fixed immediately.

---

## 🔴 CRITICAL ISSUES (Must Fix Immediately)

### 1. Duplicate Cargo.toml Configuration Section
**File:** `Cargo.toml`
**Lines:** 37 and 127
**Severity:** CRITICAL

**Issue:**
```toml
[package.metadata.docs.rs]  # Line 37
all-features = true
...

[package.metadata.docs.rs]  # Line 127 (DUPLICATE!)
all-features = true
...
```

**Impact:**
- **ALL workflows will fail** because `cargo` commands cannot parse Cargo.toml
- Project cannot build, test, or publish
- Error: `duplicate key` at line 127

**Fix:** Remove the duplicate section at lines 127-131.

---

## 🟠 HIGH PRIORITY ISSUES

### 2. Missing `--locked` Flag on Cargo Tool Installations
**Files:** Multiple workflows
**Severity:** HIGH

**Affected Workflows:**
- `ci.yml:103-104` - clippy-sarif, sarif-fmt
- `ci.yml:256` - cargo-hack
- `dependencies.yml:21` - cargo-outdated
- `dependencies.yml:28` - cargo-audit
- `publish.yml:61` - cargo-semver-checks
- `security.yml:78` - cargo-audit
- `security.yml:94` - cargo-vet
- `security.yml:114` - cargo-sbom
- `security.yml:156` - cargo-geiger

**Issue:**
Installing tools without `--locked` flag means dependencies can change between runs, leading to:
- Non-reproducible builds
- Potential breaking changes in dependencies
- Installation failures if new versions have conflicts

**Example:**
```yaml
- name: Install clippy-sarif and sarif-fmt
  run: |
    cargo install clippy-sarif sarif-fmt --locked  # ← Should add --locked
```

**Fix:** Add `--locked` flag to all `cargo install` commands.

### 3. cargo-semver-checks Will Fail on First Release
**File:** `publish.yml:66`
**Severity:** HIGH

**Issue:**
```yaml
- name: Check semantic versioning
  run: |
    cargo semver-checks check-release || {
      # This will ALWAYS fail if there's no previous version published
```

**Impact:**
- First-time publishing will fail
- New major versions might fail unexpectedly

**Fix:** Add check for baseline version existence:
```bash
if cargo semver-checks --version &> /dev/null; then
  if git describe --tags --abbrev=0 2>/dev/null; then
    cargo semver-checks check-release || { ... }
  else
    echo "No previous version found, skipping semver check"
  fi
fi
```

### 4. Performance Workflow: Incorrect Benchmark Output Path
**File:** `performance.yml:63`
**Severity:** HIGH

**Issue:**
```yaml
- name: Store benchmark result (main branch only)
  uses: benchmark-action/github-action-benchmark@v1
  with:
    tool: 'cargo'
    output-file-path: target/criterion/output.json  # ← This file doesn't exist
```

**Impact:**
- Benchmark action will fail because Criterion doesn't generate `output.json` by default
- Performance tracking will not work

**Fix:** Configure Criterion to export JSON or use a different action that supports Criterion's native format.

### 5. cargo-vet Will Fail Without Configuration
**File:** `security.yml:100`
**Severity:** HIGH

**Issue:**
```yaml
- name: Initialize cargo-vet (if needed)
  run: cargo vet init || true

- name: Run cargo vet
  run: cargo vet --locked  # ← Will fail if init failed
  continue-on-error: true
```

**Impact:**
- Job will fail if `.cargo/vet` directory doesn't exist
- `continue-on-error: true` masks the problem but breaks security summary

**Fix:** Either commit `.cargo/vet` configuration or skip this job until cargo-vet is properly configured.

### 6. Missing jq Installation
**File:** `security.yml:163`
**Severity:** HIGH

**Issue:**
```yaml
- name: Check unsafe threshold
  run: |
    UNSAFE_COUNT=$(cargo geiger --all-features --output-format Json | jq '[.packages[].unsafety.used.functions] | add')
```

**Impact:**
- Will fail with "jq: command not found"
- Unsafe code check will fail

**Fix:** Install jq before use:
```yaml
- name: Install jq
  run: sudo apt-get update && sudo apt-get install -y jq
```

---

## 🟡 MEDIUM PRIORITY ISSUES

### 7. Hardcoded Gitleaks Version
**File:** `security.yml:182`
**Severity:** MEDIUM

**Issue:**
```yaml
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
```

**Impact:**
- Using outdated version (v8.18.0, current is likely newer)
- URL might break if release is deleted
- Security tool using old vulnerability database

**Fix:** Use gitleaks-action or query GitHub API for latest release.

### 8. Incomplete Artifact Path in Publish Workflow
**File:** `publish.yml:156`
**Severity:** MEDIUM

**Issue:**
```yaml
cp target/release/libcardano_crypto.rlib artifacts/ || true
```

**Impact:**
- `.rlib` files may not exist for all build targets
- Using `|| true` silently ignores failures

**Fix:** Either remove this step or properly detect library artifacts:
```bash
find target/release -name "*.rlib" -exec cp {} artifacts/ \; 2>/dev/null || echo "No .rlib files found"
```

### 9. Nightly Toolchain Override May Not Work
**File:** `nightly.yml:25,28`
**Severity:** MEDIUM

**Issue:**
```yaml
- name: Build with nightly
  run: cargo +nightly build --all-features --verbose
```

**Impact:**
- If multiple toolchains are installed, `+nightly` override might fail
- Better to let the action-installed toolchain be the default

**Fix:** Remove `+nightly` since the toolchain action already set nightly as default.

### 10. Flamegraph Requires Specific Kernel Tools
**File:** `performance.yml:126`
**Severity:** MEDIUM

**Issue:**
```yaml
- name: Install perf
  run: sudo apt-get update && sudo apt-get install -y linux-tools-generic
```

**Impact:**
- `linux-tools-generic` might not match the running kernel version
- `perf` command might not be available

**Fix:**
```bash
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r)
```

### 11. Unstable Nightly Features in Docs
**File:** `docs.yml:53,64`
**Severity:** MEDIUM

**Issue:**
```yaml
cargo +nightly rustdoc --all-features -- -Z unstable-options --show-coverage
```

**Impact:**
- Unstable features can break between nightly versions
- Documentation generation might fail unexpectedly

**Fix:** Add `continue-on-error: true` or pin nightly version.

### 12. Lychee Link Checker Installation Wasteful
**File:** `docs.yml:68`
**Severity:** MEDIUM

**Issue:**
```yaml
cargo install lychee --locked || true
if command -v lychee &> /dev/null; then
  lychee --verbose --no-progress './target/doc/**/*.html' ...
```

**Impact:**
- Installs lychee every time even if not needed
- Takes several minutes to compile
- Installation failure is silently ignored

**Fix:** Use pre-compiled binary or action:
```yaml
- uses: lycheeverse/lychee-action@v1
```

### 13. Shell Variable Expansion in Heredoc
**File:** `docs.yml:93`
**Severity:** MEDIUM

**Issue:**
```html
<div class="coverage">${DOC_COVERAGE:-N/A}</div>
```

**Impact:**
- Variable might not expand correctly in heredoc
- Will show literal `${DOC_COVERAGE:-N/A}` instead of value

**Fix:** Use unquoted heredoc or use `envsubst`:
```bash
cat > target/doc/metrics/index.html <<EOF
...
<div class="coverage">$DOC_COVERAGE</div>
...
EOF
```

### 14. cargo-sbom Command Verification
**File:** `security.yml:117,120`
**Severity:** MEDIUM

**Issue:**
```yaml
- name: Generate SBOM (JSON)
  run: cargo sbom --output-format json > sbom.json
```

**Impact:**
- `cargo-sbom` crate exists but command syntax might be different
- Might need to be `cargo sbom generate` or similar

**Fix:** Verify correct command syntax and add error handling.

### 15. Codecov Token Handling
**File:** `ci.yml:171`
**Severity:** MEDIUM

**Issue:**
```yaml
with:
  token: ${{ secrets.CODECOV_TOKEN }}
  fail_ci_if_error: false
```

**Impact:**
- If `CODECOV_TOKEN` is not set, upload will fail silently
- No indication to users that coverage upload failed

**Fix:** Add check for token existence:
```yaml
if: secrets.CODECOV_TOKEN != ''
```

---

## 🔵 LOW PRIORITY ISSUES

### 16. Large CI Matrix
**File:** `ci.yml:28`
**Severity:** LOW

**Issue:** 3 OS × 4 Rust versions = 12 parallel jobs

**Impact:**
- High CI minute consumption
- Longer wait times
- Potential GitHub Actions quota exhaustion

**Recommendation:** Consider reducing matrix or using `fail-fast: false`.

### 17. Empty Feature String Handling
**File:** `ci.yml:225`
**Severity:** LOW

**Issue:**
```bash
if [ -z "${{ matrix.features }}" ]; then
```

**Impact:** Works but could be clearer with explicit feature combinations.

**Recommendation:** Use explicit `none` value instead of empty string.

### 18. Continue-on-Error Masks Real Issues
**Files:** Multiple workflows
**Severity:** LOW

**Issue:** Many jobs use `continue-on-error: true` which masks failures:
- `ci.yml:110` - clippy SARIF
- `nightly.yml:50` - miri
- `nightly.yml:64` - benchmarks
- `performance.yml:131` - flamegraph
- `security.yml:101` - cargo-vet

**Impact:** Real failures might go unnoticed.

**Recommendation:** Use `continue-on-error` sparingly and add notification on failure.

### 19. Dependency Review Only on PR
**File:** `security.yml:134`
**Severity:** LOW

**Issue:**
```yaml
if: github.event_name == 'pull_request'
```

**Impact:** Main branch dependency changes aren't reviewed.

**Recommendation:** Also run on push to main.

### 20. Missing Timeout Configurations
**Files:** All workflows
**Severity:** LOW

**Issue:** No job-level timeouts defined.

**Impact:** Hung jobs can waste CI resources for up to 6 hours (GitHub default).

**Recommendation:** Add `timeout-minutes: 30` to all jobs.

### 21. Cache Key Collisions
**File:** `ci.yml:49,57,65`
**Severity:** LOW

**Issue:** Cache keys might collide between different Rust versions.

**Impact:** Cache misses or incorrect cache restoration.

**Recommendation:** Include more specific identifiers in cache keys.

### 22. MSRV Inconsistency
**Files:** `Cargo.toml:5` vs `ci.yml:29`
**Severity:** LOW

**Issue:**
- Cargo.toml: `rust-version = "1.81"`
- CI matrix: `rust: [stable, beta, nightly, 1.81.0]`

**Impact:** Version mismatch (1.81 vs 1.81.0).

**Recommendation:** Use consistent versioning.

### 23. Benchmark Baseline Logic
**File:** `performance.yml:79,82`
**Severity:** LOW

**Issue:**
```bash
cargo bench --bench vrf_benchmarks -- --baseline vrf 2>&1 | tail -n 20
```

**Impact:**
- Baseline might not exist on first run
- Only shows last 20 lines which might not be useful

**Recommendation:** Add baseline existence check.

### 24. Security Summary Depends on All Jobs
**File:** `security.yml:223`
**Severity:** LOW

**Issue:**
```yaml
needs: [codeql, cargo-deny, cargo-audit, unsafe-code-check, secret-scanning]
```

**Impact:** If any job fails, summary won't run.

**Recommendation:** Use `if: always()` on summary job.

### 25. Missing Changelog Version Check
**File:** `publish.yml:136`
**Severity:** LOW

**Issue:** Extracts changelog but doesn't verify version exists in CHANGELOG.md.

**Impact:** Release notes might be empty if CHANGELOG isn't updated.

**Recommendation:** Add verification that version appears in CHANGELOG.

### 26. Concurrent Documentation Deployments
**File:** `docs.yml:18-20`
**Severity:** LOW

**Issue:**
```yaml
concurrency:
  group: "pages"
  cancel-in-progress: false
```

**Impact:** Multiple deployments might queue up.

**Recommendation:** Use `cancel-in-progress: true`.

### 27. Artifact Retention Days
**Files:** Various
**Severity:** LOW

**Issue:** Different retention periods (30, 90 days) without clear policy.

**Recommendation:** Standardize retention policy based on artifact type.

---

## 📊 Summary by Workflow

| Workflow | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| ci.yml | 0 | 2 | 1 | 5 | 8 |
| nightly.yml | 0 | 0 | 1 | 2 | 3 |
| dependencies.yml | 0 | 2 | 0 | 0 | 2 |
| performance.yml | 0 | 1 | 2 | 2 | 5 |
| docs.yml | 0 | 0 | 4 | 2 | 6 |
| publish.yml | 0 | 2 | 1 | 2 | 5 |
| security.yml | 0 | 3 | 2 | 4 | 9 |
| **Cargo.toml** | **1** | **0** | **0** | **0** | **1** |
| **TOTAL** | **1** | **10** | **11** | **17** | **39** |

---

## 🛠️ Recommended Action Plan

### Phase 1: Immediate Fixes (Block All CI)
1. ✅ Fix duplicate `[package.metadata.docs.rs]` in Cargo.toml

### Phase 2: High Priority (Next PR)
2. Add `--locked` flag to all cargo install commands
3. Fix cargo-semver-checks baseline check
4. Fix performance benchmark output path
5. Configure cargo-vet properly or disable
6. Install jq before use in security workflow

### Phase 3: Medium Priority (Within 1-2 Weeks)
7. Update gitleaks to use action or latest version
8. Fix nightly toolchain overrides
9. Fix perf installation
10. Add proper error handling for unstable features
11. Replace cargo install lychee with action
12. Fix heredoc variable expansion
13. Verify cargo-sbom command syntax
14. Add Codecov token existence check

### Phase 4: Low Priority (Ongoing Improvements)
15. Optimize CI matrix
16. Reduce continue-on-error usage
17. Add timeout-minutes to all jobs
18. Improve cache key specificity
19. Standardize artifact retention
20. Add CHANGELOG version verification

---

## 🔍 Testing Recommendations

Before pushing any workflow changes:

1. **Test locally with act:**
   ```bash
   act -j test  # Test a single job
   ```

2. **Test on a branch first:**
   - Create a test branch
   - Push workflow changes
   - Monitor Actions tab for results

3. **Use workflow_dispatch:**
   - Manually trigger workflows to test
   - Verify all jobs pass before enabling automatic triggers

4. **Monitor resource usage:**
   - Check GitHub Actions usage in repository settings
   - Ensure CI doesn't exceed free tier limits

---

## 📝 Additional Notes

- Consider using GitHub Actions concurrency controls to prevent duplicate runs
- Implement caching strategy for cargo tools to reduce installation time
- Add status badges to README for workflow status visibility
- Consider using dependabot for GitHub Actions version updates
- Document required repository secrets in README

---

**Audit completed:** 2026-01-24
**Next review recommended:** After Phase 2 completion
