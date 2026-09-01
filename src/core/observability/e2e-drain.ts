/** Shared test helper: drain a stream result's fullStream. */
export async function drain(stream: {
  fullStream: AsyncIterable<unknown>;
}): Promise<void> {
  for await (const _part of stream.fullStream) {
    // drain
  }
}
