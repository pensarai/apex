export function buildBeginHarCaptureScript(opts: {
  captureId: string;
  name: string;
}): string {
  const captureId = JSON.stringify(opts.captureId);
  const name = JSON.stringify(opts.name);

  return `async (page) => {
    const ctx = page.context();
    ctx.__apexHarCaptures = ctx.__apexHarCaptures || new Map();

    const captureId = ${captureId};
    const name = ${name};
    if (ctx.__apexHarCaptures.has(captureId)) {
      return { ok: false, error: "Capture already exists: " + captureId };
    }

    const entries = [];
    const pending = new Map();
    const bodyReads = [];

    const headersArray = (headers) =>
      Object.entries(headers || {}).map(([name, value]) => ({
        name,
        value: String(value),
      }));

    const queryArray = (url) => {
      try {
        return Array.from(new URL(url).searchParams.entries()).map(([name, value]) => ({
          name,
          value,
        }));
      } catch {
        return [];
      }
    };

    const requestBody = (request) => {
      try {
        const text = request.postData();
        if (!text) return undefined;
        return {
          mimeType: request.headers()["content-type"] || "application/octet-stream",
          text,
          _bodySize: Buffer.byteLength(text),
        };
      } catch {
        return undefined;
      }
    };

    const onRequest = (request) => {
      const startedAt = Date.now();
      const body = requestBody(request);
      pending.set(request, {
        id: captureId + "-" + (entries.length + pending.size + 1),
        startedAt,
        startedDateTime: new Date(startedAt).toISOString(),
        method: request.method(),
        url: request.url(),
        headers: headersArray(request.headers()),
        queryString: queryArray(request.url()),
        postData: body,
      });
    };

    const addEntryForResponse = async (response) => {
      const request = response.request();
      const meta = pending.get(request);
      pending.delete(request);
      if (!meta) return;

      let bodyBase64 = "";
      let bodySize = 0;
      let mimeType = response.headers()["content-type"] || "application/octet-stream";
      try {
        const body = await response.body();
        bodySize = body.length;
        bodyBase64 = Buffer.from(body).toString("base64");
      } catch {
        bodyBase64 = "";
      }

      entries.push({
        _id: meta.id,
        _started: meta.startedAt,
        startedDateTime: meta.startedDateTime,
        time: Math.max(0, Date.now() - meta.startedAt),
        request: {
          method: meta.method,
          url: meta.url,
          httpVersion: "HTTP/1.1",
          headers: meta.headers,
          queryString: meta.queryString,
          ...(meta.postData
            ? {
                postData: {
                  mimeType: meta.postData.mimeType,
                  text: meta.postData.text,
                },
              }
            : {}),
          headersSize: -1,
          bodySize: meta.postData?._bodySize ?? 0,
        },
        response: {
          status: response.status(),
          statusText: response.statusText(),
          httpVersion: "HTTP/1.1",
          headers: headersArray(await response.allHeaders().catch(() => response.headers())),
          content: {
            size: bodySize,
            mimeType,
            text: bodyBase64,
            encoding: "base64",
          },
          redirectURL: "",
          headersSize: -1,
          bodySize,
        },
        timings: { wait: Math.max(0, Date.now() - meta.startedAt) },
      });
    };

    const onResponse = (response) => {
      const read = addEntryForResponse(response);
      bodyReads.push(read);
      read.finally(() => {
        const i = bodyReads.indexOf(read);
        if (i >= 0) bodyReads.splice(i, 1);
      });
    };

    const onRequestFailed = (request) => {
      const meta = pending.get(request);
      pending.delete(request);
      if (!meta) return;
      entries.push({
        _id: meta.id,
        _started: meta.startedAt,
        startedDateTime: meta.startedDateTime,
        time: Math.max(0, Date.now() - meta.startedAt),
        request: {
          method: meta.method,
          url: meta.url,
          httpVersion: "HTTP/1.1",
          headers: meta.headers,
          queryString: meta.queryString,
          ...(meta.postData
            ? {
                postData: {
                  mimeType: meta.postData.mimeType,
                  text: meta.postData.text,
                },
              }
            : {}),
          headersSize: -1,
          bodySize: meta.postData?._bodySize ?? 0,
        },
        response: {
          status: 0,
          statusText: request.failure()?.errorText || "Request failed",
          httpVersion: "HTTP/1.1",
          headers: [],
          content: { size: 0, mimeType: "text/plain", text: "" },
          redirectURL: "",
          headersSize: -1,
          bodySize: 0,
        },
        timings: { wait: Math.max(0, Date.now() - meta.startedAt) },
      });
    };

    try {
      ctx.on("request", onRequest);
      ctx.on("response", onResponse);
      ctx.on("requestfailed", onRequestFailed);
      ctx.__apexHarCaptures.set(captureId, {
        name,
        entries,
        bodyReads,
        onRequest,
        onResponse,
        onRequestFailed,
        startedAt: new Date().toISOString(),
      });
      return { ok: true, captureId };
    } catch (error) {
      try { ctx.off("request", onRequest); } catch {}
      try { ctx.off("response", onResponse); } catch {}
      try { ctx.off("requestfailed", onRequestFailed); } catch {}
      ctx.__apexHarCaptures.delete(captureId);
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }`;
}

export function buildEndHarCaptureScript(captureId: string): string {
  const id = JSON.stringify(captureId);

  return `async (page) => {
    const ctx = page.context();
    const captures = ctx.__apexHarCaptures;
    if (!captures || !captures.has(${id})) {
      return { ok: false, error: "Unknown HAR capture: " + ${id} };
    }

    const capture = captures.get(${id});
    ctx.off("request", capture.onRequest);
    ctx.off("response", capture.onResponse);
    ctx.off("requestfailed", capture.onRequestFailed);
    captures.delete(${id});

    await Promise.allSettled(capture.bodyReads || []);
    return {
      ok: true,
      captureId: ${id},
      name: capture.name,
      startedAt: capture.startedAt,
      entries: capture.entries,
    };
  }`;
}
