# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depend on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

📧 **security@fraction.estate**

You can also report directly via GitHub's private vulnerability reporting feature:
1. Navigate to the "Security" tab in this repository
2. Click "Report a vulnerability"
3. Fill out the form with details

### What to Include

When reporting a security vulnerability, please include:

- **Type of issue** (e.g., buffer overflow, injection, authentication bypass, etc.)
- **Full paths of source file(s)** related to the issue
- **Location of the affected source code** (tag/branch/commit or direct URL)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit it

This information will help us triage your report more quickly.

### Response Timeline

- **Initial Response:** Within 48 hours of receipt
- **Confirmation & Severity Assessment:** Within 5 business days
- **Fix Development:** Depends on complexity (typically 7-30 days)
- **Public Disclosure:** Coordinated with reporter after fix is deployed

We prefer all communications to be in English.

## Security Update Process

1. **Vulnerability Reported:** Security issue is reported privately
2. **Triage:** Core team evaluates the severity and impact
3. **Development:** A fix is developed privately
4. **Testing:** The fix is thoroughly tested
5. **Release:** A security patch is released
6. **Disclosure:** After users have had time to update, details are disclosed

## Security Best Practices for Users

When using this library:

1. **Keep Updated:** Always use the latest version for security patches
2. **Review Advisories:** Check our security advisories regularly
3. **Audit Dependencies:** Use `cargo audit` to scan for known vulnerabilities
4. **Secure Key Management:** Never hardcode or commit private keys
5. **Use Proper Randomness:** Always use cryptographically secure random sources
6. **Zeroize Secrets:** The library provides automatic zeroization, but ensure you handle secrets properly in your code

## Known Security Considerations

### Cryptographic Library

This library implements production-grade cryptographic primitives. Please note:

1. **Side-Channel Resistance:** 
   - Constant-time operations are used where appropriate
   - Timing attacks are mitigated for sensitive operations
   - However, perfect side-channel resistance is impossible in software

2. **Memory Safety:**
   - Secret keys are automatically zeroized using the `zeroize` crate
   - Rust's memory safety guarantees prevent many common vulnerabilities
   - Unsafe code is minimized and audited

3. **Randomness:**
   - Users must provide properly seeded cryptographically secure random sources
   - The library does not generate random keys automatically

4. **No Audit:** 
   - This library has not undergone a formal security audit
   - Use in production at your own risk
   - Contributions to fund a security audit are welcome

### Cardano Compatibility

This library aims for 100% binary compatibility with `cardano-node`:
- All outputs match IntersectMBO/cardano-base byte-for-byte
- Test vectors from official sources are used for verification
- Any deviation from Cardano specifications is considered a security issue

## Security Advisories

We will publish security advisories through:
- GitHub Security Advisories
- RustSec Advisory Database (https://rustsec.org/)
- Project releases and changelog

## Security Hall of Fame

We would like to thank the following security researchers for responsibly disclosing vulnerabilities:

*(None yet - be the first!)*

## Bug Bounty Program

Currently, we do not have a formal bug bounty program. However, we deeply appreciate security research and will publicly acknowledge researchers who responsibly disclose vulnerabilities.

## Legal

The Fraction Estate team takes the security of our software products and services seriously.

If you believe you have found a security vulnerability in any of our repositories, please report it to us as described above.

**Please do not:**
- Exploit the vulnerability beyond what is necessary to demonstrate it
- Access or modify data that does not belong to you
- Perform actions that could negatively impact our users or services

## Attribution

This security policy is based on best practices from:
- GitHub Security Lab
- Rust Security Response WG
- OWASP Security Guidelines

## Contact

For questions about this security policy, please contact:
- Email: security@fraction.estate
- GitHub: @FractionEstate

---

**Last Updated:** 2026-01-24  
**Version:** 1.0.0
