# Command Suggestions Dropdown Research

## Problem Statement
From PR: "Using a slash shows all commands, and it leads to them being cut off if the window is too small. Command suggestions dropdown should show a limited number of commands, and the user should be able to navigate them using the arrows."

## Current Implementation Analysis

### Components Involved
1. **PromptInput** (`src/tui/components/shared/prompt-input.tsx`)
   - Main input component with autocomplete support
   - Has `maxSuggestions` prop (default: 10)
   - Already implements arrow key navigation (up/down)
   - Tab key accepts suggestions

2. **filterSuggestions** (`src/tui/components/shared/prompt-input-logic.ts`)
   - Already limits results via `.slice(0, maxSuggestions)`
   - Filters based on input matching value or label

3. **Command Context** (`src/tui/context/command.tsx`)
   - Builds `autocompleteOptions` from commands + skills
   - Currently ~15 commands registered, plus user skills

### What Currently Works
✅ Arrow key navigation exists and works
✅ Limiting suggestions exists via `maxSuggestions`
✅ Tab completion works
✅ Filtering by input prefix works

### What Doesn't Work
❌ **Visual overflow**: When `maxSuggestions=10`, all 10 items render in the DOM
   - On small terminal windows, this causes suggestions to overflow and get cut off
   - No scrolling/windowing of visible suggestions

❌ **No viewport limiting**: The suggestions box renders ALL filtered suggestions:
   ```tsx
   {suggestions.map((suggestion, index) => {
     // All suggestions are rendered, no matter the window size
   })}
   ```

## Root Cause
The issue is **rendering**, not data limiting:
- Even though we limit to 10 suggestions, we render all 10
- On a small terminal (e.g., 24 lines high), 10 suggestions + input can overflow
- Need a "windowed" view that only shows N visible suggestions at a time
- As user navigates with arrows, the window should scroll to keep selected item visible

## Solution Design

### Option 1: Reduce Default maxSuggestions ⭐
- Simply lower `maxSuggestions` default from 10 to 5-6
- Quickest fix, works for most cases
- Downside: If someone has a larger window, they can't see more suggestions

### Option 2: Implement Windowed/Scrolling Suggestions (Recommended)
- Introduce a `maxVisibleSuggestions` prop (default: 5-6)
- Show only a "window" of visible suggestions around the selected index
- As user navigates, scroll the window to keep selected item in view
- Full list is still limited by `maxSuggestions` (10), but only 5-6 show at once

Example:
```
Total suggestions: 10
maxVisibleSuggestions: 5
selectedIndex: 6

Display window shows suggestions 4-8:
  /sessions
  /new
▸ /chat         <- selected (index 6)
  /themes
  /tools
```

### Option 3: Dynamic Based on Terminal Height
- Calculate available space based on terminal dimensions
- Dynamically adjust visible suggestions
- Most complex, but most adaptive

## Recommended Implementation

**Implement Option 2** with these changes:

1. **Add `maxVisibleSuggestions` prop** to PromptInput (default: 5)
2. **Implement windowing logic** in `prompt-input-logic.ts`:
   ```ts
   export function computeVisibleWindow(
     suggestions: AutocompleteOption[],
     selectedIndex: number,
     maxVisible: number
   ): { start: number; end: number; visibleSuggestions: AutocompleteOption[] }
   ```
3. **Update rendering** in PromptInput to only render windowed suggestions
4. **Add visual indicators** for scroll state (e.g., "↑" if more above, "↓" if more below)
5. **Keep navigation working** - arrow keys already work, just need to update the window

## Files to Modify
1. `src/tui/components/shared/prompt-input.tsx` - Add windowing to render
2. `src/tui/components/shared/prompt-input-logic.ts` - Add window computation
3. `src/tui/components/shared/prompt-input-logic.test.ts` - Add tests for windowing

## Benefits
- ✅ Prevents visual overflow on small terminals
- ✅ Maintains full suggestion list (up to 10)
- ✅ Arrow navigation continues to work seamlessly
- ✅ Users with larger terminals can still see full context
- ✅ Backward compatible (all props are optional with defaults)

## Testing Plan
1. Unit tests for `computeVisibleWindow` logic
2. Manual testing with:
   - Small terminal (24 lines)
   - Medium terminal (40 lines)
   - Large terminal (60+ lines)
3. Test navigation at boundaries (top, middle, bottom of list)
4. Test with varying suggestion counts (1, 3, 5, 10+)
