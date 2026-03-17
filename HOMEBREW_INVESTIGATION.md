# Homebrew Installation Error Investigation

## Issue Summary
Users are experiencing errors when trying to install Pensar Apex via Homebrew using the commands in the README.

### Actual Error (From Screenshot)
```
Error: Formulae found in multiple taps:
  * pensarai/apex/apex
  * pensarai/tap/apex
```

### Root Cause Confirmed ✅
The user has **BOTH** taps registered:
- **Old tap**: `pensarai/apex` (deprecated)
- **New tap**: `pensarai/tap` (current)

When running `brew install apex`, Homebrew finds the formula in both taps and cannot determine which one to use, resulting in an ambiguous formula error.

## Investigation Findings

### 1. Homebrew Tap & Formula Status ✅
- **Tap Repository**: `pensarai/homebrew-tap` exists and is **public**
- **Formula File**: `Formula/apex.rb` exists and is accessible
- **Latest Version**: v0.0.101 (successfully deployed on 2026-03-17)
- **Workflow Status**: The `homebrew` job in the release workflow completed successfully

### 2. Formula Analysis

The current formula structure:
```ruby
class Apex < Formula
  desc "AI-powered penetration testing CLI tool with terminal UI"
  homepage "https://github.com/pensarai/apex"
  version "0.0.101"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/pensarai/apex/releases/download/v0.0.101/pensar-darwin-arm64.tar.gz"
      sha256 "2237deb47faaa5afa640440846a7437bfec5a107a17712e28e8c17bd56de346f"
    end
    on_intel do
      url "https://github.com/pensarai/apex/releases/download/v0.0.101/pensar-darwin-x64.tar.gz"
      sha256 "96d23b62936c0c12d7aba4a57f58a20b4e56fab03256ae202c0d4ba08df28d83"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/pensarai/apex/releases/download/v0.0.101/pensar-linux-x64.tar.gz"
      sha256 "e2f5d95a3adf1ee198dd2768f8345237314bcf67499f28b3d3a61bc32057c937"
    end
  end

  def install
    bin.install "pensar"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pensar --version")
  end
end
```

### 3. Potential Issues Identified

#### Issue #1: Missing Linux ARM64 Support 🔴
The formula only supports:
- macOS ARM (Apple Silicon)
- macOS Intel
- Linux x64 (Intel/AMD)

**Missing**: Linux ARM64 (e.g., Raspberry Pi, AWS Graviton)

If users try to install on an unsupported platform, they'll get an error like:
```
Error: apex: no bottle available!
```

#### Issue #2: License Mismatch ⚠️
- **Formula license**: `MIT`
- **Repository LICENSE file**: Likely `Apache-2.0` (based on README badge)
- **package.json license**: `MIT`

This inconsistency should be resolved.

#### Issue #3: Possible Name Collision ⚠️
While there's no `apex` formula in Homebrew core, there could be conflicts with:
- Local casks or formulae with the same name
- User-installed packages named `apex` from other sources

#### Issue #4: Binary Test Failure 🔴
The formula includes a test:
```ruby
test do
  assert_match version.to_s, shell_output("#{bin}/pensar --version")
end
```

If the binary doesn't properly respond to `--version`, installation will fail during the test phase.

#### Issue #5: Tap Not Added First 🔴
If users run `brew install apex` without first running `brew tap pensarai/tap`, they'll get:
```
Error: No available formula with the name "apex"
```

### 4. Common Homebrew Installation Errors

Based on research, users might encounter:

1. **No available formula**: Tap not added first
2. **No bottle available**: Unsupported platform (likely **Linux ARM64**)
3. **Checksum mismatch**: Corrupted download or incorrect SHA256
4. **Test failure**: Binary doesn't respond correctly to `--version`
5. **Permission errors**: Installation directory not writable

### 5. Release Workflow Analysis

The release workflow (`.github/workflows/release.yml`):
- ✅ Builds binaries for: darwin-arm64, darwin-x64, linux-x64, windows-x64
- ✅ Creates GitHub release with assets
- ✅ Calculates SHA256 checksums
- ✅ Updates Homebrew formula
- ✅ Commits and pushes to tap repository

**Missing**: Linux ARM64 build

## Root Cause: Tap Migration Conflict

### The Problem
The Homebrew tap was migrated from `pensarai/apex` to `pensarai/tap`, but users who had the old tap installed still have it registered. This creates a conflict when both taps are present.

### Why This Happened
1. The old tap repository was `pensarai/apex`
2. At some point, the tap was migrated to `pensarai/homebrew-tap` (which users access as `pensarai/tap`)
3. Users who tapped the old repository before the migration never removed it
4. The release workflow now updates `pensarai/tap`, but doesn't clean up the old `pensarai/apex` tap
5. Homebrew sees two formulas with the same name in different taps and errors out

### Impact
Any user who:
- Installed Pensar via Homebrew before the tap migration
- Still has `pensarai/apex` registered
- Tries to install or upgrade

Will encounter this error.

## Solution

### Immediate Fix for Affected Users
Users encountering this error should run:

```bash
# Remove the old deprecated tap
brew untap pensarai/apex

# Ensure the current tap is registered
brew tap pensarai/tap

# Now install apex
brew install apex
```

### Recommended Actions

#### Immediate (This PR):
1. ✅ **Add troubleshooting section to README** with tap migration instructions
2. **Document the correct installation process** clearly
3. **Add a note about the old tap** for users who might have it installed

#### Short-term:
1. **Consider deprecating the old tap repository** (if it still exists)
   - Add a README to `pensarai/apex` (if accessible) directing users to the new tap
   - Archive or delete the old tap repository if possible
2. **Fix license inconsistency**: Ensure license field is correct (MIT vs Apache-2.0)

#### Long-term:
1. **Add Linux ARM64 support**: Extend release workflow to build for linux-arm64
2. **Improve installation validation**: Add post-install smoke tests
3. **Add caveat to formula**: Consider adding a caveat that checks for and warns about the old tap

## Why This Wasn't Caught Earlier

1. **New installations work fine**: Users installing Pensar for the first time only see `pensarai/tap` and have no issues
2. **Old tap still functional**: The old tap (if it exists) may still be receiving updates, masking the problem
3. **Homebrew doesn't auto-cleanup**: When a tap is migrated, Homebrew doesn't automatically remove the old tap from users' systems

## Prevention for Future

To prevent similar issues in future tap migrations:

1. **Document tap name in AGENTS.md**: Clearly state the canonical tap name
2. **Add deprecation notices**: If migrating taps, add caveats to old formulas directing users to remove the old tap
3. **Automated cleanup**: Consider adding a post-install script that checks for and warns about conflicting taps
