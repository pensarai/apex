import type { OperatorAttachment } from "./contract";

export const MAX_ATTACHMENTS = 10;
export const MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024;

export function validateAttachmentSizes(files: { size: number }[]) {
  if (files.length > MAX_ATTACHMENTS)
    throw new Error(`Attach up to ${MAX_ATTACHMENTS} files per message.`);
  if (
    files.reduce((total, file) => total + file.size, 0) > MAX_ATTACHMENT_BYTES
  )
    throw new Error("Attachments must total 20 MB or less per message.");
}

export async function encodeAttachments(
  files: File[],
): Promise<OperatorAttachment[]> {
  validateAttachmentSizes(files);
  return Promise.all(
    files.map(
      (file) =>
        new Promise<OperatorAttachment>((resolve, reject) => {
          const reader = new FileReader();
          reader.onerror = () =>
            reject(new Error(`Could not read ${file.name}.`));
          reader.onabort = () =>
            reject(new Error(`Reading ${file.name} was cancelled.`));
          reader.onload = () => {
            const data = String(reader.result);
            resolve({
              name: file.name,
              base64: data.slice(data.indexOf(",") + 1),
            });
          };
          reader.readAsDataURL(file);
        }),
    ),
  );
}
