# Security Policy

## Dependency Supply Chain Security

This project enforces a minimum release age for all dependencies to mitigate supply chain attacks.

### Minimum Dependency Age Check

All npm dependencies must be at least **3 days old** before they can be added to the project. This provides time for the security community to identify and report potentially malicious packages.

#### Configuration

The minimum age can be configured via:

- **Environment variable**: `MIN_DEPENDENCY_AGE_DAYS` (default: 3)
- **Command line flag**: `--min-age-days N`

#### Running the Check

```bash
# Check all dependencies (including devDependencies)
bun run check:deps

# Check only production dependencies
bun run check:deps --ignore-dev

# Use custom minimum age
bun run check:deps --min-age-days 7
```

#### CI Integration

The dependency age check runs automatically on all PRs and pushes to `main`/`canary` branches as part of the CI pipeline.

#### Rationale

Supply chain attacks often involve:
1. Compromising a package maintainer's account
2. Publishing a malicious version of a popular package
3. Victims auto-installing the malicious version within hours

By enforcing a minimum age requirement, we ensure that:
- The security community has time to detect malicious packages
- Package registries and security tools can flag suspicious releases
- We're not the first adopters of potentially compromised versions

#### Exemptions

If you need to use a recently-released package (e.g., critical security patch), you can:

1. Wait for the package to meet the minimum age requirement
2. Temporarily adjust the `MIN_DEPENDENCY_AGE_DAYS` threshold with explicit approval
3. Pin to an older version of the package that meets the requirement

Always document the reason for any exemptions in the PR description.

## Reporting Security Vulnerabilities

If you discover a security vulnerability in this project, please report it to the maintainers via GitHub Security Advisories.
