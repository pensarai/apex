/* ─────────────────────────────────────────────────────────
 * ANIMATION STORYBOARD
 *
 *    0ms   the original layered gradient appears at a seeded phase
 * 0ms–∞   four wave bands drift independently while fine texture crosses
 *  every frame   native cells repaint without triggering React state
 * ───────────────────────────────────────────────────────── */

import {
  FrameBufferRenderable,
  type OptimizedBuffer,
  type RenderableOptions,
  type RenderContext,
  type RGBA,
} from "@opentui/core";
import { extend, useRenderer } from "@opentui/react";
import { useEffect } from "react";
import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import { WavePainter } from "./lib/wave-painter";

const TIMING = {
  targetFps: 12,
} as const;

type HomeGradientArtOptions = RenderableOptions<FrameBufferRenderable> & {
  artBackground?: RGBA;
  artPrimary?: RGBA;
};

class HomeGradientArtRenderable extends FrameBufferRenderable {
  private readonly painter = new WavePainter();

  constructor(ctx: RenderContext, options: HomeGradientArtOptions = {}) {
    const width = typeof options.width === "number" ? options.width : 1;
    const height = typeof options.height === "number" ? options.height : 1;
    super(ctx, {
      ...options,
      width,
      height,
      live: options.live ?? true,
      respectAlpha: false,
    });

    if (options.width !== undefined && typeof options.width !== "number") {
      this.width = options.width;
    }
    if (options.height !== undefined && typeof options.height !== "number") {
      this.height = options.height;
    }
    this.painter.setBackground(options.artBackground);
    this.painter.setPrimary(options.artPrimary);
  }

  set artBackground(value: RGBA | undefined) {
    if (this.painter.setBackground(value)) this.requestRender();
  }

  set artPrimary(value: RGBA | undefined) {
    if (this.painter.setPrimary(value)) this.requestRender();
  }

  protected override renderSelf(buffer: OptimizedBuffer, deltaTime = 0): void {
    if (!this.visible || this.isDestroyed) return;
    this.painter.render(this.frameBuffer, deltaTime);
    super.renderSelf(buffer);
  }
}

declare module "@opentui/react" {
  interface OpenTUIComponents {
    home_gradient_art: typeof HomeGradientArtRenderable;
  }
}

extend({ home_gradient_art: HomeGradientArtRenderable });

interface HomeGradientArtProps {
  height: number;
  width?: number;
}

export function HomeGradientArt({ height, width }: HomeGradientArtProps) {
  const dimensions = useDimensions();
  const { colors } = useTheme();
  const renderer = useRenderer();
  const artWidth = width ?? dimensions.width;

  useEffect(() => {
    const previousTargetFps = renderer.targetFps;
    renderer.targetFps = TIMING.targetFps;
    return () => {
      renderer.targetFps = previousTargetFps;
    };
  }, [renderer]);

  if (artWidth <= 0 || height <= 0) return null;

  return (
    <home_gradient_art
      width={artWidth}
      height={height}
      artBackground={colors.background}
      artPrimary={colors.primary}
      live
    />
  );
}
