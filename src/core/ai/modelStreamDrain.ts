export class ModelStreamDrainError extends Error {
  constructor(cause: unknown) {
    super("Model source cancellation did not confirm drain", { cause });
    this.name = "ModelStreamDrainError";
  }
}
