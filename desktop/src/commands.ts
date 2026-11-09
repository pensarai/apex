export function splitCommand(input: string): string[] {
  const words: string[] = [];
  let word = "";
  let quoted: "'" | '"' | undefined;
  let started = false;
  for (let index = 0; index < input.length; index++) {
    const char = input[index];
    const next = input[index + 1];
    if (char === "\\" && quoted !== "'" && next && /[\s"'\\]/.test(next)) {
      word += next;
      started = true;
      index++;
    } else if (quoted) {
      if (char === quoted) quoted = undefined;
      else word += char;
    } else if (char === '"' || char === "'") {
      quoted = char;
      started = true;
    } else if (/\s/.test(char)) {
      if (started) words.push(word);
      word = "";
      started = false;
    } else {
      word += char;
      started = true;
    }
  }
  if (quoted) throw new Error("Close the quoted command argument.");
  if (started) words.push(word);
  return words;
}
