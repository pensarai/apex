# OpenTUI Scrolling Guide

This guide explains how to implement proper scrolling in OpenTUI applications.

## Key Concept: Use `<scrollbox>`, Not `overflow="scroll"`

❌ **Wrong:** Using `overflow="scroll"` on regular box elements

```tsx
<box overflow="scroll">{/* content */}</box>
```

✅ **Correct:** Using the `<scrollbox>` component

```tsx
<scrollbox focused>{/* content */}</scrollbox>
```

## Test Examples

We've created several standalone test examples to demonstrate different scrolling scenarios:

### 1. `test-scroll-basic.tsx` - Basic Scrolling

The simplest scrollbox usage with static content.

**Run it:**

```bash
bun run test-scroll-basic.tsx
```

**Key features:**

- Basic vertical scrolling
- Static content (20 colored boxes)
- Arrow key and mouse wheel scrolling
- Visual scrollbar with arrows

### 2. `test-scroll-sticky.tsx` - Sticky Scroll (Chat/Logs)

Demonstrates auto-scrolling behavior perfect for chat interfaces and log viewers.

**Run it:**

```bash
bun run test-scroll-sticky.tsx
```

**Key features:**

- `stickyScroll={true}` - Maintains scroll position at edge
- `stickyStart="bottom"` - Starts scrolled to bottom
- New content automatically scrolls into view
- Manual scrolling up disables sticky until you scroll back to edge

### 3. `test-scroll-horizontal.tsx` - Horizontal + Vertical

Shows how to enable both horizontal and vertical scrolling.

**Run it:**

```bash
bun run test-scroll-horizontal.tsx
```

**Key features:**

- `scrollX={true}` - Enable horizontal scrolling
- `scrollY={true}` - Enable vertical scrolling
- Hold Shift + Scroll for horizontal scrolling

### 4. `test.tsx` - Interactive Streaming Example

Full example with auto-updating content simulating a chat interface.

**Run it:**

```bash
bun run test.tsx
```

**Key features:**

- Messages auto-add every 2 seconds
- Sticky scroll to bottom
- Streaming indicator
- Multiple layout sections

## ScrollBox API Reference

### Basic Props

```tsx
<scrollbox
  focused // Enable keyboard scrolling (arrow keys, page up/down)
  scrollY={true} // Enable vertical scrolling (default: true)
  scrollX={false} // Enable horizontal scrolling (default: false)
>
  {children}
</scrollbox>
```

### Sticky Scroll Props

Perfect for chat applications where new messages should automatically scroll into view:

```tsx
<scrollbox
  stickyScroll={true} // Enable sticky scroll behavior
  stickyStart="bottom" // Start position: "top" | "bottom" | "left" | "right"
>
  {children}
</scrollbox>
```

**How sticky scroll works:**

1. When `stickyScroll={true}` and scrolled to an edge, new content keeps you at that edge
2. Manually scrolling away from the edge disables sticky behavior
3. Scrolling back to the edge re-enables it
4. `stickyStart` sets the initial scroll position

### Style Options

The scrollbox has multiple nested renderables you can style:

```tsx
<scrollbox
  style={{
    rootOptions: {
      width: "100%",
      height: "100%",
      backgroundColor: "#1a1b26",
      flexGrow: 1,
    },
    wrapperOptions: {
      backgroundColor: "#16161e",
    },
    viewportOptions: {
      backgroundColor: "#1f2335",
    },
    contentOptions: {
      padding: 2,
      gap: 1,
      flexDirection: "column", // Layout direction for children
    },
    scrollbarOptions: {
      showArrows: true,
      trackOptions: {
        foregroundColor: "#7aa2f7",
        backgroundColor: "#414868",
      },
    },
    verticalScrollbarOptions: {
      // Specific options for vertical scrollbar
    },
    horizontalScrollbarOptions: {
      // Specific options for horizontal scrollbar
    },
  }}
>
  {children}
</scrollbox>
```

### Scrollbar Customization

```tsx
scrollbarOptions: {
  showArrows: true,              // Show arrow buttons
  trackOptions: {
    foregroundColor: "#7aa2f7",  // Thumb color
    backgroundColor: "#414868",   // Track color
  },
}
```

## Implementation in Agent Display

The `agent-display.tsx` component has been updated to use proper scrolling:

```tsx
<scrollbox
  style={{
    rootOptions: {
      width: "100%",
      height: "100%",
      flexGrow: 1,
    },
    contentOptions: {
      paddingLeft: 8,
      paddingRight: 8,
      gap: 1,
      flexDirection: "column",
    },
    scrollbarOptions: {
      showArrows: true,
    },
  }}
  stickyScroll={true}      // New messages auto-scroll
  stickyStart="bottom"     // Start at bottom
  focused                  // Enable keyboard scrolling
>
  {messages.map(...)}
</scrollbox>
```

## Common Patterns

### Chat/Messaging Interface

```tsx
<scrollbox stickyScroll={true} stickyStart="bottom" focused>
  {messages.map((msg) => (
    <box key={msg.id}>
      <text content={msg.content} />
    </box>
  ))}
</scrollbox>
```

### Log Viewer

```tsx
<scrollbox
  stickyScroll={true}
  stickyStart="bottom"
  focused
  style={{
    contentOptions: {
      gap: 0, // No gaps between log lines
    },
  }}
>
  {logs.map((log) => (
    <text key={log.id} content={log.message} />
  ))}
</scrollbox>
```

### Document Viewer

```tsx
<scrollbox
  scrollY={true}
  scrollX={true} // Enable horizontal for wide content
  focused
>
  {content}
</scrollbox>
```

### Fixed Height Container

```tsx
<box flexDirection="column" height="100%">
  <box padding={1}>
    <text content="Header" />
  </box>

  <scrollbox
    style={{
      rootOptions: {
        flexGrow: 1, // Takes remaining space
      },
    }}
    focused
  >
    {content}
  </scrollbox>

  <box padding={1}>
    <text content="Footer" />
  </box>
</box>
```

## Troubleshooting

### Content Not Scrolling

- ✅ Make sure you're using `<scrollbox>`, not `overflow="scroll"` on a box
- ✅ Add `focused` prop to enable keyboard scrolling
- ✅ Ensure the scrollbox has a defined height (via parent or `flexGrow`)
- ✅ Check that content actually exceeds viewport size

### Sticky Scroll Not Working

- ✅ Set `stickyScroll={true}`
- ✅ Set `stickyStart` to initial position
- ✅ Remember: manual scrolling disables sticky until you scroll back to edge

### Scrollbar Not Visible

- ✅ Content must exceed viewport size for scrollbar to appear
- ✅ Use `showArrows: true` in `scrollbarOptions` for better visibility
- ✅ Customize colors with `trackOptions`

### Keyboard Scrolling Not Working

- ✅ Add `focused` prop to the scrollbox
- ✅ Only one scrollbox can be focused at a time

## Architecture

OpenTUI's ScrollBox is composed of multiple nested renderables:

```
ScrollBoxRenderable (root)
├── wrapper (BoxRenderable)
│   ├── viewport (BoxRenderable)
│   │   └── content (ContentRenderable) ← Your children go here
│   └── horizontalScrollBar
└── verticalScrollBar
```

The `content` is translated (moved) based on scroll position, while `viewport` clips the visible area. This is why you configure options for each layer separately.

## Resources

- OpenTUI React Examples: `../opentui/packages/react/examples/scroll.tsx`
- ScrollBox Source: `../opentui/packages/core/src/renderables/ScrollBox.ts`
- Test Examples: `test*.tsx` files in this directory
