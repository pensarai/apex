import { describe, expect, it } from "vitest";
import {
  buildVectorString,
  calculateCVSS4Score,
  computeMacroVector,
  parseVectorString,
  validateMetrics,
} from "./calculator";
import { MACROVECTOR_LOOKUP } from "./macrovector-scores";
import { getSeverityFromScore } from "./types";

// Expected scores come from the CVSS v4.0 reference implementation FIRST hosts
// (RedHatProductSecurity/cvss-v4-calculator `cvss40.js`). The FIRST_EXAMPLES
// vectors are every CVSS 4.0 vector on https://www.first.org/cvss/v4-0/examples;
// the 18 the page prints a score for are pinned to the printed value.
//
// SWEEP_SAMPLE is a stride-419 slice of the deterministic enumeration of all
// 104,976 base-metric vectors (419 is coprime with 104,976, so it walks the
// whole space evenly). The full sweep is run offline against the reference,
// not in CI.

type Case = [vector: string, score: number];

function score(vector: string): number {
  return calculateCVSS4Score(parseVectorString(vector)).score;
}

const FIRST_EXAMPLES: Case[] = [
  // --- page prints the score ---
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 5.2],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.3],
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
    8.1,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L", 8.7],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U", 6.6],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.3],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U", 5.6],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:P", 8.6],
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P",
    9.7,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C", 8.7],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H", 6.4],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H/E:U/MAV:A/R:U/V:C",
    2.4,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MAV:L/MAT:P",
    8.9,
  ],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/MVC:N/MVI:N/MVA:N",
    0.0,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 7.1],
  // --- page links to the calculator only ---
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 4.6],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 6.9],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", 5.9],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.4],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H", 9.3],
  [
    "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D",
    8.3,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", 10.0],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A", 8.7],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3],
  [
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L",
    5.5,
  ],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H", 6.4],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I", 8.4],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/R:I", 7.1],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.0],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 8.2],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.2],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U/MVA:H/MSA:N",
    6.6,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N", 5.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N", 8.5],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/MUI:A",
    5.7,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.2],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.4],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.7],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N", 6.9],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N/E:U/CR:L/IR:L/AR:L",
    2.7,
  ],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H", 7.8],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L", 6.9],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L/MSI:N/MSA:N",
    6.9,
  ],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P", 8.5],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L",
    9.4,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:L/IR:H/AR:L/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:L/MSC:N/MSI:S/MSA:L",
    7.0,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:A/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S/CR:L/IR:H/AR:H/E:P",
    7.4,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H/CR:M/IR:H/AR:M/E:P",
    8.7,
  ],
];

// One representative per MacroVector, all 270 of them, so every
// equivalence class the algorithm keys on is pinned. Scores come from
// RedHatProductSecurity/cvss-v4-calculator, not from this implementation.
const MACROVECTOR_COVERAGE: Case[] = [
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    10.0,
  ], // 000000
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    9.9,
  ], // 000001
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    9.8,
  ], // 000010
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    9.5,
  ], // 000011
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    9.5,
  ], // 000020
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    9.2,
  ], // 000021
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    10.0,
  ], // 000100
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    9.6,
  ], // 000101
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    9.3,
  ], // 000110
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    8.7,
  ], // 000111
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    9.1,
  ], // 000120
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    8.1,
  ], // 000121
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    9.3,
  ], // 000200
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    9.0,
  ], // 000201
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    8.9,
  ], // 000210
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    8.0,
  ], // 000211
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    8.1,
  ], // 000220
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    6.8,
  ], // 000221
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.8,
  ], // 001000
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    9.5,
  ], // 001001
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    9.5,
  ], // 001010
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    9.1,
  ], // 001011
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    9.0,
  ], // 001020
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    8.3,
  ], // 001021
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    9.3,
  ], // 001100
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    9.2,
  ], // 001101
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    8.9,
  ], // 001110
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    8.1,
  ], // 001111
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    8.1,
  ], // 001120
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    6.5,
  ], // 001121
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    8.8,
  ], // 001200
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    8.0,
  ], // 001201
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    7.8,
  ], // 001210
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    7.0,
  ], // 001211
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    6.9,
  ], // 001220
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    4.7,
  ], // 001221
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.1,
  ], // 002001
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    8.1,
  ], // 002011
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    7.1,
  ], // 002021
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    7.9,
  ], // 002101
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    6.9,
  ], // 002111
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    5.0,
  ], // 002121
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    6.9,
  ], // 002201
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    5.5,
  ], // 002211
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    2.7,
  ], // 002221
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.9,
  ], // 010000
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    9.7,
  ], // 010001
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    9.5,
  ], // 010010
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    9.2,
  ], // 010011
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    9.2,
  ], // 010020
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    8.4,
  ], // 010021
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    9.5,
  ], // 010100
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    9.1,
  ], // 010101
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    9.0,
  ], // 010110
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    8.3,
  ], // 010111
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    8.4,
  ], // 010120
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    7.1,
  ], // 010121
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    9.2,
  ], // 010200
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    8.1,
  ], // 010201
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    8.2,
  ], // 010210
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    7.1,
  ], // 010211
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    7.2,
  ], // 010220
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    5.3,
  ], // 010221
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.5,
  ], // 011000
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    9.2,
  ], // 011001
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    9.2,
  ], // 011010
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    8.4,
  ], // 011011
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    8.4,
  ], // 011020
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    7.1,
  ], // 011021
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    9.2,
  ], // 011100
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    8.2,
  ], // 011101
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    8.0,
  ], // 011110
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    7.1,
  ], // 011111
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    7.0,
  ], // 011120
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    5.8,
  ], // 011121
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    8.4,
  ], // 011200
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    7.0,
  ], // 011201
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    7.1,
  ], // 011210
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    5.1,
  ], // 011211
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    5.0,
  ], // 011220
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    2.9,
  ], // 011221
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    8.5,
  ], // 012001
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    7.4,
  ], // 012011
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    5.0,
  ], // 012021
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    7.1,
  ], // 012101
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    5.2,
  ], // 012111
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    2.9,
  ], // 012121
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    6.3,
  ], // 012201
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    2.9,
  ], // 012211
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    1.7,
  ], // 012221
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.8,
  ], // 100000
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    9.5,
  ], // 100001
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    9.4,
  ], // 100010
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    8.7,
  ], // 100011
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    9.0,
  ], // 100020
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    8.0,
  ], // 100021
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    9.4,
  ], // 100100
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    8.9,
  ], // 100101
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    8.6,
  ], // 100110
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    7.4,
  ], // 100111
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    7.7,
  ], // 100120
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    6.4,
  ], // 100121
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    8.7,
  ], // 100200
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    7.5,
  ], // 100201
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    7.4,
  ], // 100210
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    6.3,
  ], // 100211
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    6.3,
  ], // 100220
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    4.9,
  ], // 100221
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.4,
  ], // 101000
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    8.8,
  ], // 101001
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    8.8,
  ], // 101010
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    7.6,
  ], // 101011
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    7.5,
  ], // 101020
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    6.6,
  ], // 101021
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    8.6,
  ], // 101100
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    7.6,
  ], // 101101
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    7.4,
  ], // 101110
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    5.8,
  ], // 101111
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    5.9,
  ], // 101120
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    4.9,
  ], // 101121
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    7.2,
  ], // 101200
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    5.7,
  ], // 101201
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    5.7,
  ], // 101210
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    5.1,
  ], // 101211
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    5.2,
  ], // 101220
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    2.5,
  ], // 101221
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    8.2,
  ], // 102001
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    7.0,
  ], // 102011
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    5.2,
  ], // 102021
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    6.5,
  ], // 102101
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    5.8,
  ], // 102111
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    2.6,
  ], // 102121
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    5.3,
  ], // 102201
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    2.1,
  ], // 102211
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    1.3,
  ], // 102221
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.5,
  ], // 110000
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    8.9,
  ], // 110001
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    8.7,
  ], // 110010
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    7.5,
  ], // 110011
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    7.5,
  ], // 110020
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    6.9,
  ], // 110021
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    9.0,
  ], // 110100
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    7.7,
  ], // 110101
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    7.5,
  ], // 110110
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    6.2,
  ], // 110111
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    6.1,
  ], // 110120
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    5.3,
  ], // 110121
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    7.7,
  ], // 110200
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    6.6,
  ], // 110201
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    6.8,
  ], // 110210
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    5.9,
  ], // 110211
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    5.2,
  ], // 110220
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    3.0,
  ], // 110221
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    8.8,
  ], // 111000
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    7.7,
  ], // 111001
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    7.5,
  ], // 111010
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    6.6,
  ], // 111011
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    6.1,
  ], // 111020
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    5.5,
  ], // 111021
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    7.4,
  ], // 111100
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    5.9,
  ], // 111101
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    5.7,
  ], // 111110
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    5.6,
  ], // 111111
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    4.7,
  ], // 111120
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    2.3,
  ], // 111121
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    6.1,
  ], // 111200
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    5.1,
  ], // 111201
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    5.7,
  ], // 111210
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    2.8,
  ], // 111211
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    2.4,
  ], // 111220
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    1.5,
  ], // 111221
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    7.0,
  ], // 112001
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    5.7,
  ], // 112011
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    2.9,
  ], // 112021
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    5.8,
  ], // 112101
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    2.6,
  ], // 112111
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    1.5,
  ], // 112121
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    2.3,
  ], // 112201
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    1.3,
  ], // 112211
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    0.6,
  ], // 112221
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    9.3,
  ], // 200000
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    8.6,
  ], // 200001
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    8.6,
  ], // 200010
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    7.2,
  ], // 200011
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    7.4,
  ], // 200020
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    5.7,
  ], // 200021
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    8.6,
  ], // 200100
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    7.4,
  ], // 200101
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    7.4,
  ], // 200110
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    6.1,
  ], // 200111
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    5.6,
  ], // 200120
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    3.4,
  ], // 200121
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    7.0,
  ], // 200200
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    5.4,
  ], // 200201
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    5.2,
  ], // 200210
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    4.0,
  ], // 200211
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    4.0,
  ], // 200220
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    2.2,
  ], // 200221
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    8.4,
  ], // 201000
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    7.4,
  ], // 201001
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    7.3,
  ], // 201010
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    5.4,
  ], // 201011
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    6.1,
  ], // 201020
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    4.8,
  ], // 201021
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    7.2,
  ], // 201100
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    5.7,
  ], // 201101
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    5.5,
  ], // 201110
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    4.0,
  ], // 201111
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    4.6,
  ], // 201120
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    1.9,
  ], // 201121
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    5.3,
  ], // 201200
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    3.6,
  ], // 201201
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    3.4,
  ], // 201210
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    1.9,
  ], // 201211
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    1.9,
  ], // 201220
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    0.8,
  ], // 201221
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    6.3,
  ], // 202001
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    4.9,
  ], // 202011
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    1.9,
  ], // 202021
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    4.7,
  ], // 202101
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    2.1,
  ], // 202111
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    1.1,
  ], // 202121
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    2.4,
  ], // 202201
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    0.9,
  ], // 202211
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    0.4,
  ], // 202221
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    8.7,
  ], // 210000
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    7.4,
  ], // 210001
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    7.2,
  ], // 210010
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    5.2,
  ], // 210011
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    5.8,
  ], // 210020
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    4.8,
  ], // 210021
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    7.3,
  ], // 210100
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    5.5,
  ], // 210101
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    5.9,
  ], // 210110
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    4.0,
  ], // 210111
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    4.1,
  ], // 210120
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    2.0,
  ], // 210121
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    5.4,
  ], // 210200
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    4.3,
  ], // 210201
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    4.5,
  ], // 210210
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    2.2,
  ], // 210211
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    2.0,
  ], // 210220
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    1.1,
  ], // 210221
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    7.4,
  ], // 211000
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M/MSI:S",
    5.5,
  ], // 211001
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    5.7,
  ], // 211010
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M/MSI:S",
    4.3,
  ], // 211011
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    3.8,
  ], // 211020
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M/MSI:S",
    2.0,
  ], // 211021
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    6.1,
  ], // 211100
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:A/CR:M/IR:M/AR:M",
    5.0,
  ], // 211101
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    4.8,
  ], // 211110
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:M/AR:M",
    1.8,
  ], // 211111
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    2.0,
  ], // 211120
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H/E:U/CR:M/IR:M/AR:M",
    0.9,
  ], // 211121
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    4.6,
  ], // 211200
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:A/CR:M/IR:M/AR:M",
    1.8,
  ], // 211201
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    1.7,
  ], // 211210
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:P/CR:M/IR:M/AR:M",
    0.7,
  ], // 211211
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    0.8,
  ], // 211220
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:H/SC:L/SI:L/SA:L/E:U/CR:M/IR:M/AR:M",
    0.2,
  ], // 211221
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H/MSI:S",
    5.1,
  ], // 212001
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H/MSI:S",
    2.3,
  ], // 212011
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H/MSI:S",
    1.3,
  ], // 212021
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:A/CR:H/IR:H/AR:H",
    2.4,
  ], // 212101
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:P/CR:H/IR:H/AR:H",
    1.2,
  ], // 212111
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:H/AR:H",
    0.5,
  ], // 212121
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:A/CR:H/IR:H/AR:H",
    1.0,
  ], // 212201
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:P/CR:H/IR:H/AR:H",
    0.3,
  ], // 212211
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:H/IR:H/AR:H",
    0.1,
  ], // 212221
];

const SWEEP_SAMPLE: Case[] = [
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:L/SI:L/SA:N", 8.8],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:L/SC:H/SI:H/SA:L", 8.5],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:L/SC:L/SI:N/SA:H", 8.4],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N", 8.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:L/SI:N/SA:L", 5.1],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:H/SI:L/SA:H", 8.5],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:N/SA:N", 8.6],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:N/VA:L/SC:H/SI:L/SA:L", 6.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:L/VA:L/SC:N/SI:H/SA:H", 8.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:N/VI:H/VA:N/SC:H/SI:L/SA:N", 8.2],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:H/SA:L", 8.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:H/SI:N/SA:H", 8.3],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:H/SC:N/SI:H/SA:N", 8.2],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L", 9.2],
  ["CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:L/VI:N/VA:L/SC:N/SI:L/SA:H", 6.0],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N", 9.0],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:L/SA:L", 8.2],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H", 7.3],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:L/SA:N", 6.0],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:L/SC:L/SI:H/SA:L", 5.1],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:H", 8.7],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:L/SI:H/SA:N", 5.1],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:L", 5.9],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:L/SI:L/SA:H", 7.1],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N", 5.9],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:L", 2.0],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:L/VA:N/SC:H/SI:H/SA:H", 5.5],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N", 7.2],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:N/VI:H/VA:H/SC:H/SI:H/SA:L", 7.1],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:H/VI:N/VA:H/SC:L/SI:N/SA:H", 6.9],
  ["CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:N/VI:L/VA:L/SC:H/SI:H/SA:N", 4.5],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:L/SI:N/SA:L", 8.3],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H", 7.0],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:N/SA:N", 2.3],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:L/VA:H/SC:H/SI:L/SA:L", 7.2],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H", 7.1],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:L/SC:H/SI:L/SA:N", 7.1],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:H/SA:L", 5.1],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:H", 7.1],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:N/SI:H/SA:N", 4.6],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:H/SC:H/SI:N/SA:L", 6.9],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:H/SC:N/SI:L/SA:H", 7.1],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:L/SC:H/SI:N/SA:N", 7.0],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:H/VI:N/VA:L/SC:N/SI:L/SA:L", 5.8],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:N/VI:L/VA:N/SC:L/SI:H/SA:H", 5.0],
  ["CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:L/VI:H/VA:N/SC:N/SI:L/SA:N", 5.7],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:H/SA:L", 9.5],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:H", 9.0],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:H/VI:L/VA:L/SC:L/SI:H/SA:N", 7.2],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:N/SA:L", 6.0],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:L/SI:L/SA:H", 7.0],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 2.1],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:L/SA:L", 6.1],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:H", 8.8],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:L/SC:L/SI:L/SA:N", 2.1],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:H/SI:H/SA:L", 7.1],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:A/VC:N/VI:H/VA:N/SC:L/SI:N/SA:H", 6.9],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:L/VI:H/VA:H/SC:H/SI:H/SA:N", 7.2],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:N/VI:N/VA:H/SC:L/SI:N/SA:L", 5.9],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:H/SI:L/SA:H", 5.0],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:L/SI:N/SA:N", 7.1],
  ["CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:H/SI:L/SA:L", 4.5],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:H/SA:H", 8.4],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:H/SI:L/SA:N", 8.4],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:H/SA:L", 8.4],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:H/SI:N/SA:H", 6.3],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:L/SC:N/SI:H/SA:N", 6.0],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:L", 9.2],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:L/SA:H", 6.2],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:H/SC:H/SI:N/SA:N", 6.8],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:N/VI:L/VA:H/SC:N/SI:L/SA:L", 5.2],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:L/VI:H/VA:L/SC:L/SI:H/SA:H", 7.1],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:N/VI:N/VA:L/SC:N/SI:L/SA:N", 2.4],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:L/SI:H/SA:L", 6.2],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:H", 8.2],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:N/VI:H/VA:H/SC:L/SI:H/SA:N", 6.9],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:H/VI:N/VA:H/SC:N/SI:N/SA:L", 5.2],
  ["CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:L/SC:L/SI:L/SA:H", 4.4],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N", 6.1],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L", 2.3],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:H/SI:H/SA:H", 7.2],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:H/SC:L/SI:L/SA:N", 5.9],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/VA:L/SC:H/SI:H/SA:L", 7.1],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:L/SC:L/SI:N/SA:H", 7.0],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:H/SI:H/SA:N", 5.1],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L", 4.3],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H", 7.2],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:A/VC:L/VI:N/VA:H/SC:L/SI:N/SA:N", 4.3],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:H/VI:L/VA:L/SC:H/SI:L/SA:L", 7.1],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:N/VI:H/VA:L/SC:N/SI:H/SA:H", 7.0],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N", 5.7],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:N/VI:L/VA:N/SC:N/SI:H/SA:L", 2.0],
  ["CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:A/VC:L/VI:L/VA:H/SC:H/SI:N/SA:H", 5.9],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N", 8.7],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:L/SC:H/SI:N/SA:L", 5.1],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:L/SC:N/SI:L/SA:H", 7.1],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:H/SI:N/SA:N", 6.9],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L", 5.7],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:L/SI:H/SA:H", 7.0],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:N/SI:L/SA:N", 5.9],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:H/VI:H/VA:L/SC:L/SI:H/SA:L", 7.0],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:L/SC:N/SI:N/SA:H", 1.8],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:H/VI:L/VA:N/SC:L/SI:H/SA:N", 5.7],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:L", 4.1],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:H/SC:L/SI:L/SA:H", 7.1],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 5.7],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 1.0],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H", 7.2],
  ["CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N", 1.0],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:H/SC:H/SI:H/SA:L", 7.3],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:L/SI:N/SA:H", 7.1],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:H/VA:L/SC:H/SI:H/SA:N", 7.1],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:N/VA:L/SC:L/SI:N/SA:L", 2.1],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:H/SI:L/SA:H", 5.0],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:N/SA:N", 7.4],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:H/SI:L/SA:L", 7.1],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:N/VA:H/SC:N/SI:H/SA:H", 5.9],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/SC:H/SI:L/SA:N", 2.0],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:N/SI:H/SA:L", 5.8],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:N/VI:N/VA:N/SC:H/SI:N/SA:H", 2.1],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:H/SA:N", 4.3],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:H/VI:L/VA:H/SC:H/SI:N/SA:L", 5.8],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:H", 5.8],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:H/VI:N/VA:L/SC:H/SI:N/SA:N", 5.6],
  ["CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:L/SC:N/SI:L/SA:L", 1.0],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:L/SI:H/SA:H", 8.4],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N", 5.1],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:L/SI:H/SA:L", 8.3],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:H/SC:N/SI:N/SA:H", 8.2],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:L/SC:L/SI:H/SA:N", 8.2],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:L", 6.9],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:H", 6.2],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N", 5.2],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L", 7.0],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:L/SC:H/SI:H/SA:H", 4.7],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:L/SI:L/SA:N", 6.8],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:L", 8.3],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:N/SC:L/SI:N/SA:H", 6.8],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:N/VI:N/VA:H/SC:H/SI:H/SA:N", 6.9],
  ["CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:L/VI:L/VA:H/SC:L/SI:N/SA:L", 5.2],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:L/SA:H", 8.8],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:L/SC:L/SI:N/SA:N", 2.1],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:H/VI:L/VA:N/SC:H/SI:L/SA:L", 7.0],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:H/SA:H", 7.0],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:L/VI:H/VA:H/SC:H/SI:L/SA:N", 7.0],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:H/SA:L", 6.8],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:N/SA:H", 4.8],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:L/SC:N/SI:H/SA:N", 6.7],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:H/SI:N/SA:L", 2.0],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:N/SI:L/SA:H", 5.7],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:N/VI:L/VA:H/SC:H/SI:N/SA:N", 5.6],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:L/VI:H/VA:H/SC:N/SI:L/SA:L", 5.7],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:L/SC:L/SI:H/SA:H", 4.7],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:L/VI:L/VA:L/SC:N/SI:L/SA:N", 1.0],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:H/VI:H/VA:N/SC:L/SI:H/SA:L", 6.9],
  ["CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:H", 1.8],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:L/SI:H/SA:N", 7.1],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:L", 5.9],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:H/VA:L/SC:L/SI:L/SA:H", 7.1],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N", 2.0],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:L", 1.8],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:H/SI:H/SA:H", 7.2],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:N", 5.8],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:H/VI:N/VA:L/SC:H/SI:H/SA:L", 5.9],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:N/VI:L/VA:L/SC:L/SI:N/SA:H", 2.0],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:H/SI:H/SA:N", 5.8],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:L", 1.0],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:H/SC:H/SI:L/SA:H", 7.0],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:H/VI:L/VA:H/SC:L/SI:N/SA:N", 4.6],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:P/VC:N/VI:H/VA:L/SC:H/SI:L/SA:L", 5.8],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:L/SC:N/SI:H/SA:H", 5.8],
  ["CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:A/VC:N/VI:L/VA:N/SC:H/SI:L/SA:N", 2.0],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:H/SA:L", 7.0],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:N/SA:H", 8.7],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:H/SA:N", 6.9],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:H/VI:L/VA:L/SC:H/SI:N/SA:L", 6.9],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:N/VI:H/VA:L/SC:N/SI:L/SA:H", 6.9],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N", 6.8],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:L", 2.0],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:H/SC:L/SI:H/SA:H", 6.0],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:L/SA:N", 5.4],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:N/VA:L/SC:L/SI:H/SA:L", 2.1],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:H", 6.8],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:N", 6.8],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:L", 4.1],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:N/VI:N/VA:H/SC:L/SI:L/SA:H", 5.8],
  ["CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:H/SC:N/SI:N/SA:N", 4.4],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L", 6.9],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:H/SI:H/SA:H", 4.7],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N", 5.2],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H/SC:H/SI:H/SA:L", 7.0],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:H/SC:L/SI:N/SA:H", 6.9],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:N", 4.4],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:L/SI:N/SA:L", 2.4],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:L/SA:H", 8.4],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N", 2.4],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:H/VI:N/VA:H/SC:H/SI:L/SA:L", 7.0],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:H/SC:N/SI:H/SA:H", 6.9],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:L/VI:H/VA:L/SC:H/SI:L/SA:N", 6.9],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:L/SC:N/SI:H/SA:L", 4.2],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:H/SI:N/SA:H", 4.4],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:H/VI:H/VA:N/SC:N/SI:H/SA:N", 8.2],
  ["CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:A/VC:N/VI:H/VA:H/SC:H/SI:N/SA:L", 6.9],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:L/SA:H", 5.8],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:N/SA:N", 1.8],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:L/SC:N/SI:L/SA:L", 4.4],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:H/SA:H", 2.3],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:L/SA:N", 1.0],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:H/VI:L/VA:H/SC:L/SI:H/SA:L", 5.9],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:H", 5.7],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:H/VI:N/VA:L/SC:L/SI:H/SA:N", 5.7],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/SC:N/SI:N/SA:L", 1.0],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:N/SC:L/SI:L/SA:H", 5.8],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:H/SC:L/SI:L/SA:L", 4.3],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:H/VI:L/VA:L/SC:H/SI:H/SA:H", 6.1],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:P/VC:N/VI:H/VA:L/SC:L/SI:L/SA:N", 4.3],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:H/VI:N/VA:N/SC:H/SI:H/SA:L", 5.9],
  ["CVSS:4.0/AV:P/AC:L/AT:P/PR:H/UI:A/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H", 2.0],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:H/SC:H/SI:H/SA:N", 5.9],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:N/SA:L", 5.4],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:L/SC:H/SI:L/SA:H", 2.3],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:H/VI:L/VA:L/SC:L/SI:N/SA:N", 4.4],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:H/SI:L/SA:L", 5.8],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:H/SA:H", 5.8],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:H/SI:L/SA:N", 5.7],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:L/VI:L/VA:H/SC:N/SI:H/SA:L", 5.8],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:L/SC:H/SI:N/SA:H", 7.0],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:L/VI:N/VA:L/SC:N/SI:H/SA:N", 1.8],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:L", 5.7],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:L/SA:H", 5.7],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:L/VI:H/VA:H/SC:H/SI:N/SA:N", 5.7],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:N/VI:N/VA:H/SC:N/SI:L/SA:L", 4.1],
  ["CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:H/SA:H", 2.3],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:L/SA:N", 5.3],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:H/SA:L", 2.1],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:H", 5.6],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H/SC:L/SI:H/SA:N", 5.7],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:L/VI:H/VA:H/SC:N/SI:N/SA:L", 4.6],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:H", 2.1],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 1.0],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:N/SC:L/SI:L/SA:L", 5.3],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H", 6.1],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:N/VA:H/SC:L/SI:L/SA:N", 4.4],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:N/VI:L/VA:L/SC:H/SI:H/SA:L", 2.3],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:L/VI:H/VA:L/SC:L/SI:N/SA:H", 5.8],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N", 2.1],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:P/VC:L/VI:L/VA:N/SC:L/SI:N/SA:L", 1.0],
  ["CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:L/VA:H/SC:H/SI:L/SA:H", 6.0],
];

const ENVIRONMENTAL_SAMPLE: Case[] = [
  [
    "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:L/SA:H/E:P/CR:H/IR:M/AR:L/MAV:N/MAT:N/MPR:H/MUI:P/MVI:N/MVA:N/MSI:S/MSA:S",
    7.0,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:L/SC:H/SI:N/SA:H/E:U/IR:M/MAV:L/MAT:N/MPR:L/MUI:N/MVC:L/MVI:L/MVA:L/MSC:H/MSI:S/MSA:L",
    4.5,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N/E:U/IR:H/AR:H/MAC:L/MAT:P/MPR:L/MUI:A/MVC:L/MVI:L/MSC:N/MSI:H/MSA:S",
    1.0,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:H/CR:L/IR:M/AR:H/MAV:N/MAC:H/MAT:N/MPR:L/MUI:A/MVC:L/MVI:H/MSA:S",
    7.4,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:L/SC:N/SI:H/SA:L/E:U/CR:H/IR:L/MAV:L/MAT:P/MPR:L/MUI:P/MVC:H/MVI:L/MVA:L/MSC:N",
    1.4,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:L/SC:L/SI:H/SA:L/E:A/IR:M/AR:M/MAV:P/MAT:P/MPR:H/MUI:P/MVC:L/MVI:H/MSC:N/MSI:L/MSA:S",
    5.4,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:L/VI:H/VA:L/SC:N/SI:H/SA:H/E:P/IR:L/AR:H/MAV:L/MAC:L/MAT:P/MPR:L/MVI:L/MVA:L/MSC:L/MSI:L/MSA:L",
    0.3,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:H/E:A/CR:M/IR:L/AR:H/MAV:N/MAT:N/MPR:N/MVC:H/MVI:H/MVA:L/MSC:N/MSI:N",
    8.9,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:H/SC:L/SI:N/SA:L/E:A/CR:M/IR:L/MAV:L/MAT:P/MPR:L/MVC:N/MSC:N/MSI:N",
    5.6,
  ],
  [
    "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:L/VI:L/VA:H/SC:N/SI:N/SA:H/E:P/CR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:P/MVC:N/MVI:N/MVA:H/MSC:N",
    4.5,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:H/E:A/CR:L/IR:L/AR:H/MAV:P/MAC:L/MAT:N/MPR:N/MVC:L/MVI:L/MVA:H/MSC:L/MSI:S/MSA:N",
    8.1,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:H/E:A/CR:H/IR:L/AR:L/MAV:P/MAC:H/MAT:N/MUI:N/MVI:L/MVA:L/MSC:N/MSI:S",
    6.9,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:L/VI:L/VA:L/SC:H/SI:H/SA:N/E:A/CR:H/IR:H/AR:L/MAV:P/MAC:H/MAT:N/MPR:N/MUI:P/MVC:N/MVI:H/MSC:H/MSA:H",
    5.9,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:H/E:U/CR:H/IR:L/AR:H/MAV:L/MAC:H/MPR:H/MUI:A/MVC:N/MVI:L/MVA:L/MSC:L/MSI:N/MSA:L",
    0.1,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:H/E:A/IR:M/AR:L/MAV:L/MAC:H/MVC:N/MVI:N/MVA:H/MSC:N/MSI:N/MSA:H",
    5.7,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:L/SC:L/SI:L/SA:N/E:P/CR:L/IR:L/AR:L/MAV:L/MAC:H/MAT:P/MUI:P/MVC:H/MVI:N/MVA:L/MSC:N/MSA:S",
    3.4,
  ],
  [
    "CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:H/SA:L/E:A/CR:H/IR:L/MAV:A/MPR:H/MUI:P/MVC:L/MVI:N/MVA:L/MSC:N",
    2.0,
  ],
  [
    "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N/E:A/CR:H/IR:H/AR:M/MAV:A/MPR:N/MVC:H/MSC:L/MSI:N/MSA:H",
    7.0,
  ],
  [
    "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:H/SC:L/SI:N/SA:L/E:P/CR:M/IR:M/AR:M/MAV:A/MPR:H/MVC:L/MVI:H/MVA:N/MSC:L/MSA:S",
    6.2,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:H/VI:L/VA:H/SC:L/SI:N/SA:H/E:U/IR:L/AR:L/MAV:N/MAT:P/MPR:H/MVI:L/MSI:L",
    3.5,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:L/E:A/CR:M/IR:H/MAV:P/MUI:P/MVC:H/MVA:N/MSC:H/MSI:S/MSA:N",
    5.4,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:N/VC:L/VI:H/VA:N/SC:L/SI:N/SA:N/E:A/CR:M/IR:H/AR:L/MAV:A/MAT:N/MUI:A/MVC:N/MVI:H/MVA:N/MSC:H/MSI:N",
    5.5,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:H/SA:N/E:U/MAV:A/MAC:L/MAT:N/MPR:H/MUI:N/MVC:N/MSI:H/MSA:S",
    4.4,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:N/SI:L/SA:N/E:A/IR:L/MAV:A/MAC:L/MUI:N/MVC:N/MSI:N/MSA:L",
    7.0,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:H/SA:N/E:U/CR:L/IR:H/AR:L/MAV:L/MAC:L/MAT:P/MPR:H/MUI:P/MVC:H/MVI:L/MVA:H/MSC:L/MSI:L/MSA:N",
    0.2,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:L/SA:H/CR:H/IR:L/MAV:P/MPR:L/MUI:N/MVI:H/MVA:N/MSI:L/MSA:S",
    8.2,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/CR:L/IR:L/MAV:L/MAT:P/MPR:H/MUI:N/MVC:H/MVA:N/MSC:L/MSI:N",
    4.5,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:N/VI:N/VA:L/SC:L/SI:H/SA:N/E:U/CR:L/IR:M/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MVC:N/MVI:L/MSC:H/MSI:N/MSA:L",
    0.3,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:H/SI:H/SA:H/CR:H/IR:H/MAT:N/MPR:H/MSC:L/MSI:S/MSA:H",
    8.3,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L/CR:L/AR:M/MPR:N/MUI:N/MVI:L/MVA:L/MSI:S/MSA:N",
    9.1,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:H/SI:N/SA:H/E:U/CR:L/AR:M/MAC:L/MAT:P/MVC:N/MVI:N/MVA:N/MSC:H/MSI:S/MSA:S",
    2.6,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:L/SC:N/SI:H/SA:N/E:P/CR:L/IR:H/AR:H/MAV:P/MAT:P/MPR:H/MUI:N/MVC:H/MVI:L/MVA:L/MSI:N/MSA:L",
    0.7,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:H/SC:L/SI:N/SA:L/E:P/CR:H/IR:M/AR:H/MAV:A/MAC:L/MAT:N/MPR:N/MVC:L/MVI:N/MVA:L/MSC:H/MSI:H/MSA:H",
    5.8,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:H/SI:L/SA:L/E:U/CR:M/IR:M/AR:L/MPR:L/MVC:H/MVA:N/MSI:L/MSA:L",
    4.5,
  ],
  [
    "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H/CR:M/AR:L/MAV:P/MAC:L/MAT:P/MPR:N/MUI:N/MVC:N/MVI:N/MVA:L/MSC:N/MSI:S/MSA:S",
    4.8,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:H/SA:N/E:A/IR:H/AR:H/MAV:L/MAC:L/MAT:N/MPR:L/MUI:A/MVI:N/MVA:L/MSC:H/MSI:S/MSA:S",
    6.4,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:H/SI:L/SA:N/CR:L/IR:L/AR:M/MAV:L/MAC:L/MAT:P/MPR:N/MVC:H/MVI:N/MVA:H/MSC:N/MSI:L/MSA:H",
    5.7,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:L/SC:L/SI:H/SA:N/IR:M/AR:M/MAC:H/MAT:N/MPR:L/MUI:N/MVC:N/MVI:H/MVA:H/MSC:L/MSI:N/MSA:S",
    7.5,
  ],
  [
    "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:H/E:U/CR:L/IR:L/MAV:A/MAC:H/MAT:P/MPR:L/MUI:A/MVC:L/MSC:H/MSI:S",
    1.9,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:L/E:P/CR:H/IR:H/AR:L/MAV:P/MAC:H/MAT:P/MUI:P/MVA:N/MSC:N/MSI:L",
    3.8,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:H/E:U/CR:H/AR:M/MAV:P/MPR:N/MUI:N/MVC:L/MVI:H/MVA:L/MSC:H/MSI:S",
    3.6,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:N/VC:L/VI:H/VA:H/SC:H/SI:H/SA:L/E:A/IR:H/AR:H/MAV:P/MAC:H/MAT:N/MPR:H/MUI:P/MVI:L/MSC:L/MSI:L",
    4.4,
  ],
  [
    "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:H/SC:H/SI:H/SA:L/IR:M/AR:M/MAV:P/MAC:H/MAT:N/MVI:H/MVA:N/MSC:L/MSI:S/MSA:S",
    8.5,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:U/AR:M/MAV:N/MAC:L/MAT:N/MPR:N/MUI:A/MVC:H/MVI:N/MVA:N/MSC:H/MSA:L",
    5.6,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:H/SI:L/SA:H/E:A/CR:H/IR:M/MAV:A/MAC:L/MAT:P/MUI:P/MVC:H/MVI:L/MSI:S/MSA:L",
    8.7,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:H/IR:L/AR:L/MAC:L/MAT:N/MPR:N/MUI:P/MVC:H/MSC:H/MSI:L/MSA:S",
    9.3,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:L/VI:N/VA:N/SC:L/SI:H/SA:N/E:U/CR:M/IR:L/AR:M/MAV:L/MAC:H/MAT:N/MPR:L/MVI:N/MSC:L/MSI:N/MSA:S",
    0.8,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:L/SI:N/SA:N/E:P/CR:L/IR:M/MAV:A/MAC:L/MAT:N/MPR:L/MVC:H/MVI:H/MVA:H/MSC:L/MSA:H",
    6.9,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:L/SC:N/SI:H/SA:L/E:P/CR:L/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:H/MUI:N/MVC:L/MVI:L/MSC:N",
    2.2,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:P/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N/IR:H/MAV:L/MAC:H/MAT:P/MPR:N/MUI:A/MVC:N/MVA:H/MSC:N/MSI:L/MSA:S",
    8.4,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:P/VC:H/VI:N/VA:H/SC:L/SI:L/SA:N/CR:H/IR:H/AR:L/MAV:P/MAC:L/MAT:P/MPR:N/MUI:N/MVI:N/MSC:N/MSI:S/MSA:N",
    6.9,
  ],
  [
    "CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:L/E:A/IR:H/AR:H/MAV:N/MAC:L/MAT:P/MUI:A/MVC:H/MVA:L/MSI:N/MSA:S",
    9.3,
  ],
  [
    "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:H/SC:L/SI:H/SA:N/E:A/CR:M/IR:L/AR:L/MAV:P/MPR:L/MUI:N/MVC:H/MVI:N/MSI:L/MSA:S",
    5.4,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:L/VI:N/VA:L/SC:L/SI:L/SA:H/E:P/CR:M/AR:L/MAV:N/MAC:H/MAT:N/MPR:N/MUI:N/MVA:N/MSC:H/MSI:S/MSA:L",
    7.2,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:N/VI:N/VA:L/SC:N/SI:L/SA:L/E:A/CR:M/IR:L/AR:H/MAV:P/MAC:H/MUI:N/MVI:N/MVA:L/MSI:H/MSA:S",
    4.6,
  ],
  [
    "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:H/VI:L/VA:L/SC:L/SI:H/SA:H/CR:L/IR:H/MAV:N/MUI:P/MVI:L/MVA:N/MSC:H/MSI:L/MSA:S",
    7.3,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:P/PR:H/UI:N/VC:H/VI:N/VA:H/SC:L/SI:L/SA:N/CR:L/IR:H/AR:L/MAC:L/MPR:H/MUI:A/MVC:L/MVI:H/MVA:H/MSC:L/MSI:N/MSA:L",
    3.9,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:N/VI:H/VA:L/SC:H/SI:N/SA:L/CR:H/IR:M/MAV:A/MAC:H/MPR:H/MUI:P/MVC:N/MVA:H/MSC:L/MSI:H",
    5.8,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:L/E:P/CR:M/IR:M/AR:L/MAC:L/MAT:N/MPR:H/MUI:P/MVC:H/MVI:L/MVA:H/MSC:H/MSI:S/MSA:N",
    7.3,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:L/SI:H/SA:L/AR:H/MAT:P/MPR:N/MUI:A/MVC:N/MVI:L/MVA:H/MSC:N/MSI:L/MSA:L",
    5.8,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:H/E:U/IR:L/AR:H/MAV:A/MAT:P/MPR:L/MVC:H/MVI:H/MVA:L/MSC:N/MSI:S/MSA:H",
    7.1,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:H/SA:L/E:U/AR:M/MAV:A/MAC:H/MPR:H/MVC:N/MVI:H/MVA:N/MSC:N/MSI:H",
    3.4,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:H/IR:H/MAV:A/MAC:H/MAT:P/MUI:P/MVI:H/MVA:H/MSC:L/MSI:L",
    7.0,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U/CR:H/IR:L/MAV:L/MAC:H/MAT:N/MUI:N/MVC:L/MVI:N/MVA:H/MSI:S/MSA:H",
    5.7,
  ],
  [
    "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/CR:M/IR:M/AR:H/MAC:L/MAT:N/MUI:N/MVI:L/MVA:N/MSI:L/MSA:L",
    5.5,
  ],
  [
    "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/CR:M/IR:L/MAV:L/MAC:H/MPR:N/MUI:P/MVI:N/MSI:L/MSA:S",
    7.3,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/E:A/CR:L/AR:M/MAC:H/MAT:P/MPR:H/MUI:A/MVC:H/MVI:H/MSC:L/MSI:H/MSA:S",
    8.4,
  ],
  [
    "CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N/E:A/CR:H/IR:L/AR:H/MAV:A/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:N/MSC:H/MSI:H/MSA:L",
    9.3,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:N/SA:H/E:A/CR:L/IR:H/MAV:A/MAT:N/MPR:N/MUI:N/MVC:L/MVI:H/MSC:N/MSI:H/MSA:H",
    7.2,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:N/VA:L/SC:L/SI:L/SA:N/E:U/CR:H/IR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:P/MVI:L/MVA:L/MSC:N/MSI:N/MSA:L",
    0.5,
  ],
  [
    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N/E:P/CR:L/IR:L/AR:L/MAV:P/MAT:P/MPR:H/MUI:N/MVC:H/MVA:H/MSC:L/MSI:S/MSA:H",
    3.8,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:P/IR:M/AR:L/MAV:P/MAC:H/MAT:N/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:H/MSA:S",
    2.1,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:L/SI:H/SA:L/E:P/IR:L/MAV:N/MAT:P/MPR:H/MUI:P/MVA:H/MSC:N",
    5.6,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:L/SI:N/SA:L/CR:M/IR:M/AR:M/MAC:L/MUI:N/MVC:H/MSI:L/MSA:L",
    5.5,
  ],
  [
    "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:N/CR:H/IR:L/MAV:A/MAT:P/MPR:L/MUI:P/MVC:N/MSC:H/MSA:N",
    2.1,
  ],
  [
    "CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:A/VC:N/VI:L/VA:L/SC:H/SI:N/SA:N/E:U/CR:M/IR:M/MAT:N/MUI:N/MVC:L/MVA:N/MSC:N/MSI:N/MSA:S",
    4.1,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:L/SA:H/E:A/IR:H/AR:M/MPR:H/MUI:A/MVC:L/MVI:H/MVA:H/MSC:H/MSA:S",
    7.3,
  ],
  [
    "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:H/E:A/IR:M/AR:H/MAV:A/MAT:N/MPR:L/MUI:N/MVC:H/MSC:H/MSI:S",
    8.7,
  ],
  [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:N/SI:H/SA:N/E:A/CR:M/IR:L/MAV:A/MAC:L/MAT:P/MPR:H/MUI:A/MVC:L/MVI:N/MSC:N/MSA:N",
    1.8,
  ],
  [
    "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:N/E:U/CR:M/IR:L/AR:M/MAV:P/MAC:H/MUI:A/MVC:N/MVI:H/MVA:N/MSI:S/MSA:N",
    1.6,
  ],
];

describe("calculateCVSS4Score", () => {
  it.each(
    FIRST_EXAMPLES,
  )("scores the FIRST example %s as %f", (vector, expected) => {
    expect(score(vector)).toBe(expected);
  });

  it.each(
    SWEEP_SAMPLE,
  )("scores the base vector %s as %f", (vector, expected) => {
    expect(score(vector)).toBe(expected);
  });

  it.each(
    MACROVECTOR_COVERAGE,
  )("scores %s as %f, covering its MacroVector", (vector, expected) => {
    expect(score(vector)).toBe(expected);
  });

  it("pins every MacroVector in the lookup table", () => {
    const covered = new Set(
      MACROVECTOR_COVERAGE.map(([vector]) =>
        computeMacroVector(parseVectorString(vector)),
      ),
    );
    expect(covered.size).toBe(Object.keys(MACROVECTOR_LOOKUP).length);
  });

  it.each(ENVIRONMENTAL_SAMPLE)("scores %s as %f", (vector, expected) => {
    expect(score(vector)).toBe(expected);
  });

  it("scores 0.0 when nothing is impacted", () => {
    const result = calculateCVSS4Score(
      parseVectorString(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
      ),
    );
    expect(result.score).toBe(0);
    expect(result.severity).toBe("NONE");
  });

  it("scores 0.0 when modified metrics remove every impact", () => {
    expect(
      score(
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/MVC:N/MVI:N/MVA:N",
      ),
    ).toBe(0);
  });

  it("reports the score type from the metric groups supplied", () => {
    const base =
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    expect(calculateCVSS4Score(parseVectorString(base)).scoreType).toBe(
      "CVSS-B",
    );
    expect(
      calculateCVSS4Score(parseVectorString(`${base}/E:P`)).scoreType,
    ).toBe("CVSS-BT");
    expect(
      calculateCVSS4Score(parseVectorString(`${base}/CR:L`)).scoreType,
    ).toBe("CVSS-BE");
    expect(
      calculateCVSS4Score(parseVectorString(`${base}/E:P/MAV:L`)).scoreType,
    ).toBe("CVSS-BTE");
  });
});

describe("severity distance from the MacroVector max", () => {
  // The distance is level(actual) - level(max vector of this MacroVector), not
  // level(actual). A vector that IS its MacroVector's max keeps the table score.
  it("leaves a MacroVector's own max vector at the table score", () => {
    expect(
      score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"),
    ).toBe(10);
    expect(
      score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ).toBe(9.3);
  });

  it("penalises only the distance from that max", () => {
    expect(
      score("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ).toBe(8.6);
    expect(
      score("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ).toBe(7);
    expect(
      score("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"),
    ).toBe(4.8);
  });

  it("resolves the joint EQ3/EQ6 step down", () => {
    // eq3=0, eq6=0: the lower MacroVector is the better of stepping EQ3 or EQ6.
    expect(
      computeMacroVector(
        parseVectorString(
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        ),
      ),
    ).toBe("000200");
    expect(
      score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N"),
    ).toBe(9.3);
    // eq3=1, eq6=0: the lower MacroVector steps EQ6, not EQ3.
    expect(
      computeMacroVector(
        parseVectorString(
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N",
        ),
      ),
    ).toBe("001200");
    expect(
      score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ).toBe(8.8);
  });

  it("rounds half up with an epsilon so 9.95 does not fall to 9.9", () => {
    expect(
      score(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
      ),
    ).toBe(10);
  });
});

describe("computeMacroVector", () => {
  it("puts AV:N/PR:N/UI:N in EQ1=0", () => {
    expect(
      computeMacroVector(
        parseVectorString(
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        ),
      )[0],
    ).toBe("0");
  });

  it("puts PR:H or UI:A in EQ1=1 while one of AV/PR/UI is None", () => {
    for (const vector of [
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    ]) {
      expect(computeMacroVector(parseVectorString(vector))[0]).toBe("1");
    }
  });

  it("puts AV:P in EQ1=2, and EQ1=2 when none of AV/PR/UI is None", () => {
    for (const vector of [
      "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    ]) {
      expect(computeMacroVector(parseVectorString(vector))[0]).toBe("2");
    }
  });

  it("treats CR:X/IR:X/AR:X as High in EQ6", () => {
    const base =
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    expect(computeMacroVector(parseVectorString(base))).toBe(
      computeMacroVector(parseVectorString(`${base}/CR:X/IR:X/AR:X`)),
    );
    expect(score(base)).toBe(score(`${base}/CR:X/IR:X/AR:X`));
    expect(score(`${base}/CR:L/IR:L/AR:L`)).not.toBe(score(base));
  });

  it("treats E:X as Attacked in EQ5", () => {
    const base =
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    expect(score(`${base}/E:X`)).toBe(score(`${base}/E:A`));
    expect(score(`${base}/E:P`)).toBe(8.9);
    expect(score(`${base}/E:U`)).toBe(8.1);
  });

  it("puts MSI:S / MSA:S in EQ4=0", () => {
    const base =
      "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L";
    expect(computeMacroVector(parseVectorString(`${base}/MSI:S`))[3]).toBe("0");
    expect(computeMacroVector(parseVectorString(`${base}/MSA:S`))[3]).toBe("0");
    expect(score(`${base}/MSI:S`)).toBe(7.8);
    expect(score(`${base}/MSA:S`)).toBe(7.8);
  });

  it("prefers a modified metric over its base metric", () => {
    const base =
      "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    expect(score(`${base}/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N`)).toBe(
      score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    );
  });
});

describe("vector strings", () => {
  it("round-trips a base vector", () => {
    const vector =
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    expect(buildVectorString(parseVectorString(vector))).toBe(vector);
  });

  it("emits metrics in specification order and drops Not Defined", () => {
    expect(
      buildVectorString(
        parseVectorString(
          "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:L/E:P/CR:X",
        ),
      ),
    ).toBe(
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAV:L",
    );
  });

  it("rejects a vector that is not CVSS 4.0", () => {
    expect(() =>
      parseVectorString("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ).toThrow(/CVSS:4.0/);
  });

  it("rejects a vector missing a base metric", () => {
    expect(() =>
      parseVectorString("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"),
    ).toThrow(/SC/);
  });
});

describe("validateMetrics", () => {
  it("accepts a complete set of base metrics", () => {
    expect(
      validateMetrics({
        AV: "N",
        AC: "L",
        AT: "N",
        PR: "N",
        UI: "N",
        VC: "H",
        VI: "H",
        VA: "H",
        SC: "N",
        SI: "N",
        SA: "N",
      }),
    ).toBe(true);
  });

  it("rejects an incomplete set", () => {
    expect(validateMetrics({ AV: "N", AC: "L" })).toBe(false);
  });
});

describe("getSeverityFromScore", () => {
  it("maps each band boundary", () => {
    expect(getSeverityFromScore(0)).toBe("NONE");
    expect(getSeverityFromScore(0.1)).toBe("LOW");
    expect(getSeverityFromScore(3.9)).toBe("LOW");
    expect(getSeverityFromScore(4)).toBe("MEDIUM");
    expect(getSeverityFromScore(6.9)).toBe("MEDIUM");
    expect(getSeverityFromScore(7)).toBe("HIGH");
    expect(getSeverityFromScore(8.9)).toBe("HIGH");
    expect(getSeverityFromScore(9)).toBe("CRITICAL");
    expect(getSeverityFromScore(10)).toBe("CRITICAL");
  });
});
