import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { MAX_ATTACHMENT_BYTES, validateAttachmentSizes } from "./attachments";
import type { OperatorAttachment } from "./contract";

export function decodeAttachments(files: OperatorAttachment[] = []) {
  if (!Array.isArray(files)) throw new Error("Invalid attachments.");
  validateAttachmentSizes(files.map(() => ({ size: 0 })));
  let total = 0;
  return files.map((file) => {
    if (
      typeof file?.name !== "string" ||
      !file.name.trim() ||
      file.name.length > 1024 ||
      typeof file.base64 !== "string" ||
      file.base64.length > Math.ceil(MAX_ATTACHMENT_BYTES / 3) * 4
    )
      throw new Error("Invalid file attachment.");
    const bytes = Buffer.from(file.base64, "base64");
    if (bytes.toString("base64") !== file.base64)
      throw new Error("Invalid file attachment encoding.");
    total += bytes.length;
    validateAttachmentSizes([{ size: total }]);
    return { name: file.name, bytes };
  });
}

export async function attachFilesToPrompt(
  rootPath: string,
  text: string,
  files: ReturnType<typeof decodeAttachments>,
) {
  if (!files.length) return text;
  const directory = await mkdtemp(join(rootPath, "attachments-"));
  try {
    const references: string[] = [];
    for (const [index, file] of files.entries()) {
      let name = file.name.replace(/[<>:"/\\|?*\p{Cc}]/gu, "_");
      while (Buffer.byteLength(name) > 200) name = name.slice(0, -1);
      name = name.replace(/[. ]+$/g, "") || "file";
      const path = join(directory, `${index + 1}-${name}`);
      await writeFile(path, file.bytes, { flag: "wx", mode: 0o600 });
      references.push(
        `- ${JSON.stringify(file.name)}: ${JSON.stringify(path)}`,
      );
    }
    return `${text.trim() || "Please analyze the attached files."}\n\nAttached files (local copies; use file tools to inspect):\n${references.join("\n")}`;
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
