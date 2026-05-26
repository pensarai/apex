import { z } from "zod";

export const HarHeaderSchema = z
  .object({
    name: z.string(),
    value: z.string(),
  })
  .passthrough();

const HarPostDataSchema = z
  .object({
    mimeType: z.string().optional(),
    text: z.string().optional(),
  })
  .passthrough();

const HarRequestSchema = z
  .object({
    method: z.string(),
    url: z.string(),
    httpVersion: z.string().optional(),
    headers: z.array(HarHeaderSchema).default([]),
    queryString: z.array(HarHeaderSchema).default([]),
    postData: HarPostDataSchema.optional(),
    headersSize: z.number().optional(),
    bodySize: z.number().optional(),
  })
  .passthrough();

const HarContentSchema = z
  .object({
    size: z.number(),
    mimeType: z.string().optional(),
    text: z.string().optional(),
    encoding: z.string().optional(),
    _attachedSha: z.string().optional(),
    _attachedPath: z.string().optional(),
  })
  .passthrough();

const HarResponseSchema = z
  .object({
    status: z.number(),
    statusText: z.string().optional(),
    httpVersion: z.string().optional(),
    headers: z.array(HarHeaderSchema).default([]),
    content: HarContentSchema,
    redirectURL: z.string().optional(),
    headersSize: z.number().optional(),
    bodySize: z.number().optional(),
  })
  .passthrough();

export const HarEntrySchema = z
  .object({
    _id: z.string().optional(),
    _started: z.number().optional(),
    startedDateTime: z.string(),
    time: z.number(),
    request: HarRequestSchema,
    response: HarResponseSchema,
    timings: z.record(z.number()).optional(),
    pageref: z.string().optional(),
  })
  .passthrough();

export const HarFileSchema = z
  .object({
    log: z
      .object({
        version: z.string(),
        creator: z
          .object({
            name: z.string(),
            version: z.string(),
          })
          .optional(),
        entries: z.array(HarEntrySchema),
      })
      .passthrough(),
  })
  .passthrough();

export type HarHeader = z.infer<typeof HarHeaderSchema>;
export type HarEntry = z.infer<typeof HarEntrySchema>;
export type HarFile = z.infer<typeof HarFileSchema>;

export function parseHar(input: unknown): HarFile {
  const value = typeof input === "string" ? JSON.parse(input) : input;
  return HarFileSchema.parse(value);
}
