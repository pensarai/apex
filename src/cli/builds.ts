#!/usr/bin/env bun

/**
 * pensar builds — Upload desktop-app build artifacts to the Pensar Console
 *
 * All commands operate on the selected workspace (set via `pensar login`).
 *
 * Usage:
 *   pensar builds upload <file> --app <ref> --version <v> --platform <p> [opts]
 */

import {
  type ArtifactPlatform,
  type ReleaseChannel,
  uploadDesktopBuild,
} from "../core/api/builds";

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

const PLATFORMS: ArtifactPlatform[] = ["linux", "windows", "macos"];
const CHANNELS: ReleaseChannel[] = ["stable", "beta", "nightly", "dev"];

function showHelp(): void {
  console.log(`pensar builds — Upload desktop-app build artifacts

All commands operate on the selected workspace (set via \`pensar login\`).

Usage:
  pensar builds upload <file> [options]

upload options (required):
  --app <ref>            Application id or label (e.g. APP-3) the build belongs to
  --version <v>          Release version, e.g. 1.4.2
  --platform <p>         Target OS: linux | windows | macos

upload options (optional):
  --arch <a>             Architecture: x64 (default) | arm64 | universal
  --channel <c>          Release channel: stable (default) | beta | nightly | dev
  --format <f>           Package format (auto-detected from the filename if omitted)
  --content-type <ct>    Override the upload Content-Type
  --commit <sha>         Source commit SHA (provenance)
  --repo-id <uuid>       Source repository id (provenance)
  --ref <ref>            Source branch/tag (provenance)
  --repo-path <path>     Monorepo subpath the build came from (provenance)
  --build-url <url>      CI build/run URL (provenance)
  --ci                   Mark the release sourceKind as "ci"

Options:
  -h, --help             Show this help message

Examples:
  pensar builds upload ./dist/app-1.4.2.AppImage --app APP-3 --version 1.4.2 --platform linux
  pensar builds upload ./dist/App.exe --app APP-3 --version 1.4.2 --platform windows --arch x64 \\
    --ci --commit $GITHUB_SHA --repo-id <uuid> --build-url $RUN_URL`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];

  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    showHelp();
    return;
  }

  if (sub !== "upload") {
    console.error(`Error: Unknown subcommand "${sub}"`);
    showHelp();
    process.exit(1);
  }

  const filePath = args[1] && !args[1].startsWith("--") ? args[1] : undefined;
  const application = getFlag("--app", args);
  const version = getFlag("--version", args);
  const platform = getFlag("--platform", args) as ArtifactPlatform | undefined;

  const missing: string[] = [];
  if (!filePath) missing.push("<file>");
  if (!application) missing.push("--app");
  if (!version) missing.push("--version");
  if (!platform) missing.push("--platform");
  if (missing.length > 0) {
    console.error(`Error: missing required argument(s): ${missing.join(", ")}`);
    console.error(
      "Usage: pensar builds upload <file> --app <ref> --version <v> --platform <p>",
    );
    process.exit(1);
  }
  if (!PLATFORMS.includes(platform as ArtifactPlatform)) {
    console.error(`Error: --platform must be one of: ${PLATFORMS.join(", ")}`);
    process.exit(1);
  }
  const channel = getFlag("--channel", args) as ReleaseChannel | undefined;
  if (channel && !CHANNELS.includes(channel)) {
    console.error(`Error: --channel must be one of: ${CHANNELS.join(", ")}`);
    process.exit(1);
  }

  const source = {
    repositoryId: getFlag("--repo-id", args),
    commitSha: getFlag("--commit", args),
    ref: getFlag("--ref", args),
    repositoryPath: getFlag("--repo-path", args),
    buildUrl: getFlag("--build-url", args),
  };
  const hasSource = Object.values(source).some((v) => v !== undefined);

  try {
    console.error(`Uploading ${filePath} …`);
    const artifact = await uploadDesktopBuild({
      filePath: filePath as string,
      application: application as string,
      version: version as string,
      platform: platform as ArtifactPlatform,
      architecture: getFlag("--arch", args),
      channel,
      format: getFlag("--format", args),
      contentType: getFlag("--content-type", args),
      sourceKind: args.includes("--ci") ? "ci" : undefined,
      source: hasSource ? source : undefined,
    });
    console.log(JSON.stringify(artifact, null, 2));
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}

main();
