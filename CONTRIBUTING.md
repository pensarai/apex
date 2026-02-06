# Contributing to Apex

Thank you for your interest in contributing to Apex! We welcome contributions from the community.

## Reporting Bugs

If you find a bug, please report it by [creating a GitHub issue](https://github.com/pensarai/apex/issues/new). Include as much detail as possible:

- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Your environment (OS, Node/Bun version, etc.)

## Suggesting Fixes

If you'd like to suggest a fix for a bug:

1. Open a GitHub issue describing the bug (if one doesn't already exist)
2. Fork the repository and create a branch for your fix
3. Make your changes
4. Open a pull request linked to the issue

## Before Submitting a PR

Please ensure the following before submitting your pull request:

1. **Run the tests** to make sure your changes don't break existing functionality:

   ```bash
   bun run test
   ```

2. **Ensure TypeScript checks pass** with no type errors:

   ```bash
   tsc --noEmit
   ```

## Development Setup

1. Clone the repository
2. Install dependencies with `bun install`
3. Run `bun run dev` to start the development watcher

## Questions?

If you have questions, feel free to open an issue and we'll be happy to help.
