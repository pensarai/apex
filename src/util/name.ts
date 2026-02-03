// Random name generator (GitHub-style)
const adjectives = [
  "swift", "bright", "calm", "bold", "keen", "noble", "quick", "sharp",
  "vivid", "warm", "agile", "brave", "clever", "daring", "eager", "fierce",
  "gentle", "humble", "jolly", "lively", "merry", "nimble", "proud", "quiet",
  "rapid", "serene", "sturdy", "tender", "valiant", "witty", "zealous"
];

const nouns = [
  "falcon", "wolf", "hawk", "bear", "lion", "tiger", "eagle", "raven",
  "phoenix", "dragon", "panther", "cobra", "viper", "shark", "orca",
  "mantis", "spider", "scorpion", "hydra", "griffin", "sphinx", "kraken",
  "cipher", "nexus", "prism", "vector", "matrix", "pulse", "surge", "flux"
];

export function generateRandomName(): string {
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)]!;
  const noun = nouns[Math.floor(Math.random() * nouns.length)]!;
  return `${adj}-${noun}`;
}