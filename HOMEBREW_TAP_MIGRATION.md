# Homebrew Tap Migration Guide

## Background

Pensar Apex's Homebrew tap was migrated from `pensarai/apex` to `pensarai/tap`. This follows Homebrew's naming convention where tap repositories are named `homebrew-{name}` and accessed as `{org}/{name}`.

## If You're Experiencing Installation Errors

### The Error
If you see this error when running `brew install apex`:

```
Error: Formulae found in multiple taps:
  * pensarai/apex/apex
  * pensarai/tap/apex
```

### The Cause
You have both the old (deprecated) tap and the new tap registered on your system. Homebrew doesn't know which one to use.

### The Solution

Run these commands to remove the old tap and use the new one:

```bash
# 1. Remove the old deprecated tap
brew untap pensarai/apex

# 2. Ensure the current tap is registered
brew tap pensarai/tap

# 3. Install or upgrade apex
brew install apex
# or
brew upgrade apex
```

## Fresh Installation

If you're installing Pensar Apex for the first time, simply run:

```bash
brew tap pensarai/tap
brew install apex
```

## Verification

To verify you're using the correct tap:

```bash
# List all tapped repositories
brew tap

# You should see "pensarai/tap" in the list
# You should NOT see "pensarai/apex" in the list
```

To verify your installation:

```bash
# Check the installed version
pensar --version

# Check which tap the formula came from
brew info apex
```

## Additional Notes

- The formula is named `apex`, but it installs the `pensar` binary
- Only the tap name changed; the formula name (`apex`) remained the same
- The old tap (`pensarai/apex`) is deprecated and should not be used

## Supported Platforms

Homebrew installation is supported on:
- macOS (Apple Silicon and Intel)
- Linux (x64/AMD64)

For other platforms, consider:
- **npm**: `npm install -g @pensar/apex`
- **Quick install script**: `curl -fsSL https://pensarai.com/install.sh | bash`

## Need Help?

If you continue to experience issues after following this guide:

1. Check the [troubleshooting section](./README.md#troubleshooting-homebrew-installation) in the README
2. Open an issue on [GitHub](https://github.com/pensarai/apex/issues)
3. Include the output of:
   ```bash
   brew tap
   brew --version
   brew config
   uname -a
   ```
