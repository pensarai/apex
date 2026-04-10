import { describe, expect, it } from "vitest";

import { validatePocPortability } from "./documentFinding";

describe("validatePocPortability", () => {
  describe("bash scripts", () => {
    it("detects grep -oP (Perl regex)", () => {
      const script = `#!/bin/bash
response=$(curl -s http://target.com/api/test)
id=$(echo "$response" | grep -oP '(?<=id":)[0-9]+')
echo "ID: $id"`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
      expect(warnings[0]).toContain("grep -E");
    });

    it("detects grep -P (Perl regex)", () => {
      const script = `#!/bin/bash
grep -P 'pattern' file.txt`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("grep -P or grep -oP");
    });

    it("detects bc usage", () => {
      const script = `#!/bin/bash
result=$(echo "scale=2; 10 / 3" | bc)
echo "Result: $result"`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("bc command detected");
      expect(warnings[0]).toContain("$(( ))");
    });

    it("does not warn about bc if it's checked first", () => {
      const script = `#!/bin/bash
if command -v bc >/dev/null 2>&1; then
  result=$(echo "scale=2; 10 / 3" | bc)
else
  result=$(python3 -c "print(10/3)")
fi`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });

    it("detects GNU stat -c flag", () => {
      const script = `#!/bin/bash
stat -c '%s' /path/to/file`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("stat -c");
      expect(warnings[0]).toContain("GNU-specific");
    });

    it("detects GNU date long options", () => {
      const script = `#!/bin/bash
date --rfc-3339=seconds`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("GNU date long options");
    });

    it("detects seq usage", () => {
      const script = `#!/bin/bash
for i in $(seq 1 10); do
  echo $i
done`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("seq");
      expect(warnings[0]).toContain("brace expansion");
    });

    it("does not warn about seq if it's checked first", () => {
      const script = `#!/bin/bash
if which seq >/dev/null 2>&1; then
  for i in $(seq 1 10); do echo $i; done
else
  for i in {1..10}; do echo $i; done
fi`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });

    it("detects multiple portability issues", () => {
      const script = `#!/bin/bash
id=$(curl -s http://target.com | grep -oP '(?<=id":)[0-9]+')
result=$(echo "scale=2; $id / 3" | bc)
stat -c '%s' /tmp/output
date --rfc-3339=seconds`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings.length).toBeGreaterThanOrEqual(4);
      expect(warnings.some((w) => w.includes("grep -P"))).toBe(true);
      expect(warnings.some((w) => w.includes("bc"))).toBe(true);
      expect(warnings.some((w) => w.includes("stat -c"))).toBe(true);
      expect(warnings.some((w) => w.includes("date"))).toBe(true);
    });

    it("returns empty array for portable bash script", () => {
      const script = `#!/bin/bash
set -e

response=$(curl -s http://target.com/api/test)
id=$(echo "$response" | grep -oE '"id":[0-9]+' | grep -oE '[0-9]+')

# Use shell arithmetic instead of bc
count=$((id * 2))

for i in {1..10}; do
  echo "Test iteration $i"
  curl -X POST "http://target.com/api/item/$id"
done

echo "Success: exploited endpoint with ID $id"
exit 0`;

      const warnings = validatePocPortability(script, "bash");

      expect(warnings).toHaveLength(0);
    });
  });

  describe("python scripts", () => {
    it("returns empty array for python scripts", () => {
      const script = `#!/usr/bin/env python3
import requests
response = requests.get('http://target.com')
print(response.text)`;

      const warnings = validatePocPortability(script, "python");

      expect(warnings).toHaveLength(0);
    });

    it("does not validate portability for python", () => {
      // Even with bash-style commands in comments or strings,
      // we don't validate Python scripts
      const script = `#!/usr/bin/env python3
# This grep -oP would fail on macOS
import subprocess
subprocess.run(['grep', '-E', 'pattern'])`;

      const warnings = validatePocPortability(script, "python");

      expect(warnings).toHaveLength(0);
    });
  });

  describe("javascript scripts", () => {
    it("returns empty array for javascript scripts", () => {
      const script = `#!/usr/bin/env node
const axios = require('axios');
axios.get('http://target.com')
  .then(response => console.log(response.data));`;

      const warnings = validatePocPortability(script, "javascript");

      expect(warnings).toHaveLength(0);
    });
  });
});
