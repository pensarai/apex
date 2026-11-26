import { memo, useLayoutEffect, useMemo, useRef } from "react";
import { LocalMarkdown } from "../view/LocalMarkdown";
import { advanceStream, streamFadePlugin } from "./stream-fade";

export const StreamingMarkdown = memo(function StreamingMarkdown({
  text,
  visible,
  fresh,
  sessionId,
}: {
  text: string;
  visible: boolean;
  fresh: boolean;
  sessionId?: string;
}) {
  const previous = useRef({
    text: fresh ? "" : text,
    arrivals: [],
  } as ReturnType<typeof advanceStream>);
  const render = useMemo(() => {
    const now = performance.now();
    const state = advanceStream(previous.current, text, now, visible);
    return {
      state,
      options: { rehypePlugins: [streamFadePlugin(state.arrivals, now)] },
    };
  }, [text, visible]);
  useLayoutEffect(() => {
    previous.current = render.state;
  }, [render]);
  return (
    <LocalMarkdown text={text} options={render.options} sessionId={sessionId} />
  );
});
