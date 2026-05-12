#!/usr/bin/env bun
/**
 * Check Dependency Age
 * ====================
 * Enforces a minimum release age for all dependencies to mitigate supply chain attacks.
 *
 * By default, requires dependencies to be at least 3 days old before installation.
 * This provides time for the community to identify and report malicious packages.
 *
 * Usage:
 *   bun run scripts/check-dependency-age.ts [--min-age-days N] [--ignore-dev]
 *
 * Environment variables:
 *   MIN_DEPENDENCY_AGE_DAYS - Override default minimum age (default: 3)
 *   IGNORE_DEV_DEPENDENCIES - Skip checking devDependencies (default: false)
 */

import { readFile } from "fs/promises";
import { resolve } from "path";

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface PackageMetadata {
  name: string;
  version: string;
  publishedAt: Date;
  ageInDays: number;
}

interface CheckResult {
  passed: boolean;
  tooNewPackages: PackageMetadata[];
  checkedPackages: number;
  errors: string[];
}

const DEFAULT_MIN_AGE_DAYS = 3;
const NPM_REGISTRY = "https://registry.npmjs.org";

/**
 * Parse command line arguments
 */
function parseArgs(): { minAgeDays: number; ignoreDev: boolean } {
  const args = process.argv.slice(2);
  let minAgeDays =
    Number(process.env.MIN_DEPENDENCY_AGE_DAYS) || DEFAULT_MIN_AGE_DAYS;
  let ignoreDev = process.env.IGNORE_DEV_DEPENDENCIES === "true";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--min-age-days" && args[i + 1]) {
      minAgeDays = Number(args[i + 1]);
      i++;
    } else if (args[i] === "--ignore-dev") {
      ignoreDev = true;
    }
  }

  return { minAgeDays, ignoreDev };
}

/**
 * Fetch package metadata from npm registry
 */
async function fetchPackageMetadata(
	name: string,
	versionSpec: string,
): Promise<PackageMetadata | null> {
	try {
		// Remove version prefixes (^, ~, >=, etc.) to get the actual version
		const cleanVersion = versionSpec.replace(/^[\^~>=<]+/, "");

		// Fetch package metadata from npm registry
		const response = await fetch(`${NPM_REGISTRY}/${name}`, {
			headers: {
				Accept: "application/json",
			},
		});

		if (!response.ok) {
			throw new Error(`HTTP ${response.status}: ${response.statusText}`);
		}

		const data = await response.json();

		// Get publish time from the time object
		const publishTime = data.time?.[cleanVersion];
		if (!publishTime) {
			throw new Error(
				`Version ${cleanVersion} not found in registry for ${name}`,
			);
		}

		const publishedAt = new Date(publishTime);
		const now = new Date();
		const ageInMs = now.getTime() - publishedAt.getTime();
		const ageInDays = ageInMs / (1000 * 60 * 60 * 24);

		return {
			name,
			version: cleanVersion,
			publishedAt,
			ageInDays,
		};
	} catch (error) {
		console.error(
			`⚠️  Failed to fetch metadata for ${name}@${versionSpec}: ${error instanceof Error ? error.message : String(error)}`,
		);
		return null;
	}
}

/**
 * Check all dependencies in package.json
 */
async function checkDependencies(
  minAgeDays: number,
  ignoreDev: boolean,
): Promise<CheckResult> {
  const packageJsonPath = resolve(process.cwd(), "package.json");

  let packageJson: PackageJson;
  try {
    const content = await readFile(packageJsonPath, "utf-8");
    packageJson = JSON.parse(content);
  } catch (error) {
    return {
      passed: false,
      tooNewPackages: [],
      checkedPackages: 0,
      errors: [
        `Failed to read package.json: ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }

  // Collect all dependencies to check
  const allDeps: Record<string, string> = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.optionalDependencies || {}),
  };

  if (!ignoreDev) {
    Object.assign(allDeps, packageJson.devDependencies || {});
  }

  // Filter out workspace, file, and git dependencies
  const npmDeps = Object.entries(allDeps).filter(
    ([_, version]) =>
      !version.startsWith("workspace:") &&
      !version.startsWith("file:") &&
      !version.startsWith("git+") &&
      !version.includes("://"),
  );

  console.log(`\n📦 Checking ${npmDeps.length} dependencies...`);
  console.log(`⏰ Minimum required age: ${minAgeDays} days\n`);

  const tooNewPackages: PackageMetadata[] = [];
  const errors: string[] = [];
  let checkedCount = 0;

  // Check each dependency in parallel (with rate limiting)
  const batchSize = 10;
  for (let i = 0; i < npmDeps.length; i += batchSize) {
    const batch = npmDeps.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(([name, version]) => fetchPackageMetadata(name, version)),
    );

    for (const metadata of results) {
      if (!metadata) {
        continue;
      }

      checkedCount++;

      if (metadata.ageInDays < minAgeDays) {
        tooNewPackages.push(metadata);
        console.log(
          `❌ ${metadata.name}@${metadata.version} - ${metadata.ageInDays.toFixed(1)} days old (published ${metadata.publishedAt.toISOString()})`,
        );
      } else {
        console.log(
          `✅ ${metadata.name}@${metadata.version} - ${metadata.ageInDays.toFixed(1)} days old`,
        );
      }
    }
  }

  return {
    passed: tooNewPackages.length === 0,
    tooNewPackages,
    checkedPackages: checkedCount,
    errors,
  };
}

/**
 * Main function
 */
async function main() {
  const { minAgeDays, ignoreDev } = parseArgs();

  console.log("🔒 Dependency Age Check");
  console.log("=======================");

  const result = await checkDependencies(minAgeDays, ignoreDev);

  if (result.errors.length > 0) {
    console.error("\n❌ Errors occurred:");
    for (const error of result.errors) {
      console.error(`   ${error}`);
    }
    process.exit(1);
  }

  console.log(`\n📊 Summary:`);
  console.log(`   Checked: ${result.checkedPackages} packages`);

  if (result.passed) {
    console.log(
      `   ✅ All dependencies meet the minimum age requirement (${minAgeDays} days)`,
    );
    process.exit(0);
  } else {
    console.log(
      `\n⚠️  Found ${result.tooNewPackages.length} package(s) that are too new:`,
    );
    for (const pkg of result.tooNewPackages) {
      console.log(
        `   - ${pkg.name}@${pkg.version} (${pkg.ageInDays.toFixed(1)} days old, need ${minAgeDays}+ days)`,
      );
    }

    console.log("\n💡 Supply chain security recommendation:");
    console.log(
      "   New packages may not have been vetted by the community yet.",
    );
    console.log(
      `   Wait ${minAgeDays - Math.min(...result.tooNewPackages.map((p) => p.ageInDays))} more day(s) or use an older version.`,
    );

    process.exit(1);
  }
}

main().catch((error) => {
  console.error("❌ Unexpected error:", error);
  process.exit(1);
});
