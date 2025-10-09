# OpenTUI Scrolling Quick Reference

## ❌ Don't Do This

```tsx
<box overflow="scroll">
  {" "}
  {/* WRONG - doesn't work properly */}
  {content}
</box>
```

## ✅ Do This Instead

### Basic Scrolling

```tsx
<scrollbox focused>{content}</scrollbox>
```

### Chat/Message Interface (Auto-scroll to bottom)

```tsx
<scrollbox
  stickyScroll={true}
  stickyStart="bottom"
  focused
>
  {messages.map(...)}
</scrollbox>
```

### Custom Styling

```tsx
<scrollbox
  style={{
    rootOptions: {
      width: "100%",
      height: "100%",
      flexGrow: 1,
    },
    contentOptions: {
      padding: 2,
      gap: 1,
      flexDirection: "column",
    },
    scrollbarOptions: {
      showArrows: true,
      trackOptions: {
        foregroundColor: "#7aa2f7",
        backgroundColor: "#414868",
      },
    },
  }}
  focused
>
  {content}
</scrollbox>
```

### Horizontal + Vertical

```tsx
<scrollbox scrollX={true} scrollY={true} focused>
  {content}
</scrollbox>
```

## Run Tests

```bash
bun test:scroll              # Interactive streaming
bun test:scroll:basic        # Basic example
bun test:scroll:sticky       # Chat/log example
bun test:scroll:horizontal   # Horizontal scrolling
```

## Key Props

| Prop           | Type    | Description                                        |
| -------------- | ------- | -------------------------------------------------- |
| `focused`      | boolean | Enable keyboard scrolling                          |
| `stickyScroll` | boolean | Auto-scroll when at edge                           |
| `stickyStart`  | string  | Initial position: "top", "bottom", "left", "right" |
| `scrollX`      | boolean | Enable horizontal (default: false)                 |
| `scrollY`      | boolean | Enable vertical (default: true)                    |
| `style`        | object  | Styling options for all nested components          |

## Style Options

```tsx
style={{
  rootOptions: { ... },              // Outer container
  wrapperOptions: { ... },           // Wrapper layer
  viewportOptions: { ... },          // Visible area
  contentOptions: { ... },           // Your content (padding, gap, etc)
  scrollbarOptions: { ... },         // Both scrollbars
  verticalScrollbarOptions: { ... }, // Vertical only
  horizontalScrollbarOptions: { ... } // Horizontal only
}
```

## Common Issues

**Not scrolling?**

- ✅ Use `<scrollbox>`, not `overflow="scroll"`
- ✅ Add `focused` prop
- ✅ Ensure container has height

**Sticky scroll not working?**

- ✅ Set `stickyScroll={true}`
- ✅ Set `stickyStart="bottom"`

**Keyboard not working?**

- ✅ Add `focused` prop

## More Info

See `SCROLLING_GUIDE.md` for complete documentation.
