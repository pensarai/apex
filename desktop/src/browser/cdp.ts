export type CdpEvent = {
  method: string;
  params: Record<string, unknown>;
  sessionId?: string;
};

export class CdpConnection {
  private nextId = 0;
  private pending = new Map<
    number,
    {
      resolve: (value: unknown) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private constructor(
    private socket: WebSocket,
    onEvent: (event: CdpEvent) => void,
  ) {
    socket.onmessage = (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id === undefined) {
        onEvent(message);
        return;
      }
      const pending = this.pending.get(message.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
    };
    socket.onclose = () => this.failPending();
    socket.onerror = () => this.close();
  }
  static async connect(
    endpoint: string,
    onEvent: (event: CdpEvent) => void = () => {},
  ) {
    const socket = new WebSocket(endpoint);
    await new Promise<void>((resolve, reject) => {
      const finish = (error?: Error) => {
        clearTimeout(timer);
        socket.onopen = socket.onerror = socket.onclose = null;
        if (error) {
          socket.close();
          reject(error);
        } else resolve();
      };
      const timer = setTimeout(
        () => finish(new Error("Browser connection timed out.")),
        10000,
      );
      socket.onopen = () => finish();
      socket.onerror = socket.onclose = () =>
        finish(new Error("Browser connection failed."));
    });
    return new CdpConnection(socket, onEvent);
  }
  send<T = Record<string, never>>(
    method: string,
    params: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<T> {
    if (this.socket.readyState !== WebSocket.OPEN)
      return Promise.reject(new Error("Browser connection closed."));
    const id = ++this.nextId;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Browser command timed out: ${method}`));
      }, 15000);
      this.pending.set(id, {
        resolve: (value) => resolve(value as T),
        reject,
        timer,
      });
      try {
        this.socket.send(JSON.stringify({ id, method, params, sessionId }));
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
  }
  private failPending() {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Browser connection closed."));
    }
    this.pending.clear();
  }
  close() {
    this.failPending();
    this.socket.close();
  }
}
