import { describe, it, expect, vi } from "vitest";
import { StreamIdleTimeoutError, withIdleTimeout } from "./ai";

describe("withIdleTimeout", () => {
  it("passes through chunks when stream is healthy", async () => {
    async function* source() {
      yield "a";
      yield "b";
      yield "c";
    }

    const collected: string[] = [];
    for await (const chunk of withIdleTimeout(source(), 1000)) {
      collected.push(chunk);
    }
    expect(collected).toEqual(["a", "b", "c"]);
  });

  it("throws StreamIdleTimeoutError when stream stalls", async () => {
    async function* stallingSource() {
      yield "a";
      // Stall forever after first chunk
      await new Promise(() => {});
    }

    const collected: string[] = [];
    await expect(async () => {
      for await (const chunk of withIdleTimeout(stallingSource(), 50)) {
        collected.push(chunk);
      }
    }).rejects.toThrow(StreamIdleTimeoutError);

    expect(collected).toEqual(["a"]);
  });

  it("throws StreamIdleTimeoutError when stream never yields", async () => {
    // eslint-disable-next-line require-yield -- intentional: tests timeout when source never produces
    async function* neverYields() {
      await new Promise(() => {});
    }

    await expect(async () => {
      for await (const _chunk of withIdleTimeout(neverYields(), 50)) {
        // should not reach here
      }
    }).rejects.toThrow(StreamIdleTimeoutError);
  });

  it("resets the idle timer on each chunk", async () => {
    async function* slowButAlive() {
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 30));
        yield i;
      }
    }

    const collected: number[] = [];
    for await (const chunk of withIdleTimeout(slowButAlive(), 80)) {
      collected.push(chunk);
    }
    expect(collected).toEqual([0, 1, 2, 3, 4]);
  });

  it("calls iterator.return on timeout to clean up the source", async () => {
    const returnSpy = vi
      .fn()
      .mockResolvedValue({ done: true, value: undefined });

    const fakeIterable: AsyncIterable<string> = {
      [Symbol.asyncIterator]() {
        let first = true;
        return {
          async next() {
            if (first) {
              first = false;
              return { done: false as const, value: "a" };
            }
            return new Promise(() => {});
          },
          return: returnSpy,
        };
      },
    };

    const collected: string[] = [];
    try {
      for await (const chunk of withIdleTimeout(fakeIterable, 50)) {
        collected.push(chunk);
      }
    } catch {
      // expected
    }

    expect(collected).toEqual(["a"]);
    expect(returnSpy).toHaveBeenCalled();
  });
});

describe("StreamIdleTimeoutError", () => {
  it("has the correct name and message", () => {
    const err = new StreamIdleTimeoutError(300_000);
    expect(err.name).toBe("StreamIdleTimeoutError");
    expect(err.message).toBe("Stream idle for 300s — no chunks received");
    expect(err).toBeInstanceOf(Error);
  });
});
