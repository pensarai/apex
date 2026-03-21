import type { BuiltInSkill } from "../types";
import { THREAT_MODEL_INSTRUCTIONS } from "./threatModelInstructions";

export const threatModelSkill: BuiltInSkill = {
  slug: "threat-model",
  manifest: {
    name: "Threat Model",
    description:
      "Generate an application-centric threat model from source code analysis",
    tags: ["security", "threat-modeling", "whitebox"],
    inputs: [
      {
        name: "output",
        description: "Output file path (default: ./threat-model.md)",
        required: false,
      },
    ],
  },
  instructions: THREAT_MODEL_INSTRUCTIONS,
};
