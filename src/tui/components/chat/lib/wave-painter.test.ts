import { type OptimizedBuffer, RGBA } from "@opentui/core";
import { describe, expect, it } from "vitest";
import { WavePainter } from "./wave-painter";

function createBuffer(width: number, height: number): OptimizedBuffer {
  const cellCount = width * height;
  return {
    width,
    height,
    buffers: {
      char: new Uint32Array(cellCount),
      fg: new Uint16Array(cellCount * 4),
      bg: new Uint16Array(cellCount * 4),
      attributes: new Uint32Array(cellCount),
    },
  } as unknown as OptimizedBuffer;
}

describe("WavePainter", () => {
  it("advances according to elapsed time instead of render count", () => {
    const singleStepPainter = new WavePainter();
    const splitStepPainter = new WavePainter();
    const singleStepBuffer = createBuffer(80, 8);
    const splitStepBuffer = createBuffer(80, 8);

    singleStepPainter.render(singleStepBuffer, 1_000);
    splitStepPainter.render(splitStepBuffer, 500);
    splitStepPainter.render(splitStepBuffer, 500);

    expect([...singleStepBuffer.buffers.char]).toEqual([
      ...splitStepBuffer.buffers.char,
    ]);
  });

  it("changes the field as time advances", () => {
    const painter = new WavePainter();
    const buffer = createBuffer(80, 8);

    painter.render(buffer);
    const firstFrame = [...buffer.buffers.char];
    painter.render(buffer, 1_000);

    expect([...buffer.buffers.char]).not.toEqual(firstFrame);
  });

  it("writes the original row gradient and theme background", () => {
    const painter = new WavePainter();
    const buffer = createBuffer(8, 2);
    const background = RGBA.fromInts(4, 8, 12);
    const primary = RGBA.fromInts(40, 180, 90);

    painter.setBackground(background);
    painter.setPrimary(primary);
    painter.render(buffer);

    expect([...buffer.buffers.bg.slice(0, 4)]).toEqual([...background.buffer]);
    expect([...buffer.buffers.fg.slice(0, 4)]).not.toEqual([
      ...buffer.buffers.fg.slice(buffer.buffers.fg.length - 4),
    ]);
  });
});
