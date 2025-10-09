# Text content becomes invisible during rapid updates (streaming)

## Summary

When updating text content rapidly (e.g., streaming AI responses), the text becomes completely invisible after the initial render, though the layout space is correctly allocated. **A single update works perfectly, but multiple rapid updates cause invisible text - even when throttled to 500ms intervals.**

## Environment

- **opentui/react version**: 0.1.25
- **opentui/core version**: 0.1.25
- **React version**: 19.1.1
- **Node version**: 20.18.1
- **Runtime**: Bun
- **Platform**: macOS (darwin 25.0.0)
- **Terminal**: Ghostty

## Expected Behavior

Text content should update and remain visible during streaming, similar to how the counter example updates every 50ms.

## Actual Behavior

- ✅ User message (first, static message) displays perfectly
- ✅ Assistant message label displays ("← Assistant" in green)
- ❌ Assistant message **content is completely invisible** (but space is allocated)
- Console logs confirm data is correct and component is re-rendering
- Strange semicolon-like artifacts (;;;) appear where text should be

## Minimal Reproduction

```tsx
import { useState } from "react";
import { render } from "@opentui/react";

function StreamingText() {
  const [text, setText] = useState("");
  const [started, setStarted] = useState(false);

  async function startStreaming() {
    setStarted(true);
    let content = "";

    // Simulate streaming chunks
    for (let i = 0; i < 50; i++) {
      content += `Chunk ${i} `;
      setText(content);
      await new Promise((resolve) => setTimeout(resolve, 100)); // Even with 100ms delay!
    }
  }

  return (
    <box flexDirection="column" gap={1}>
      {!started && (
        <text fg="cyan" content="Press Enter to start (call startStreaming)" />
      )}

      <box flexDirection="column">
        <text fg="green">Label (always visible)</text>
        <text fg="white">{text}</text>
      </box>
    </box>
  );
}

render(<StreamingText />);
```

**Result**: The label shows but the streaming text is invisible (layout space allocated but no visible characters).

## What We Tested

All attempts failed except showing only the final result:

1. ❌ **Using `content` prop**: `<text content={text} />` instead of `<text>{text}</text>`
2. ❌ **Different key strategies**:
   - Stable keys: `key={index}`
   - Dynamic keys: `key={`${index}-${content.length}`}`
   - Per-element keys on text component
3. ❌ **Removed `style={{ overflow: "scroll" }}`**: Was using on parent box
4. ❌ **Different colors**: `fg="white"`, `fg="cyan"`, `fg="magenta"`
5. ❌ **Throttled to 500ms**: Only 2 updates per second still fails
6. ❌ **Throttled to 100ms**: 10 updates per second still fails
7. ✅ **Single update after completion**: **THIS WORKS**

## Key Finding

```tsx
// ❌ DOESN'T WORK - Text invisible during updates
for await (const chunk of stream) {
  content += chunk;
  setText(content);
  await new Promise((resolve) => setTimeout(resolve, 500)); // Even with delay!
}

// ✅ WORKS - Text visible
for await (const chunk of stream) {
  content += chunk;
}
setText(content); // Single update after all chunks
```

## Observations

- The counter example (`examples/counter.tsx`) works with 50ms updates
- Our streaming text with 500ms updates (2 Hz) fails
- Difference: Counter updates a short number, we update longer growing strings
- User message (static, one update) always displays correctly
- Assistant streaming message (multiple updates) is always invisible
- Text buffer appears to allocate space but not render/flush properly

## Possible Root Cause

Looking at `packages/core/src/renderables/Text.ts`:

```typescript
set content(value: StyledText | string) {
  this._hasManualStyledText = true
  const styledText = typeof value === "string" ? stringToStyledText(value) : value
  if (this._text !== styledText) {  // Reference comparison
    this._text = styledText
    this.updateTextBuffer(styledText)
    this.updateTextInfo()
  }
}
```

Possible issues:

1. Text buffer not flushing between rapid updates
2. React reconciliation not properly triggering updates for text nodes with changing content
3. Race condition between `updateTextBuffer` and render cycle
4. Difference in how short vs long text content is handled

## Workaround

Currently forced to disable streaming UX:

```tsx
// Accumulate all chunks silently
let content = "";
for await (const chunk of stream) {
  content += chunk;
}
// Only update UI once at the end
setText(content);
```

## Impact

- Blocks implementation of streaming AI interfaces
- Requires choosing between real-time updates (invisible) or delayed display (bad UX)
- Counter-intuitive since single updates work fine

## Questions

1. Is there a recommended pattern for streaming/rapidly updating text?
2. What's different about the counter example that makes it work?
3. Is there a text buffer flush or render cycle we're missing?
4. Any known limitations with updating text content multiple times?
