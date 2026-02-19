import { Renderable, ScrollBoxRenderable } from "@opentui/core";

/**
 * Scrolls a ScrollBox to keep the item at `index` visible.
 * Finds the target element by matching `id` within nested child groups
 * (e.g., date-grouped session lists).
 */
export function scrollToIndex<T extends { id: string }>(
  scrollBox: ScrollBoxRenderable | null,
  index: number,
  list: T[],
) {
  if (!scrollBox || list.length === 0) return;

  const target = findChildById(scrollBox, list[index]?.id);
  if (!target) return;

  // First item — scroll to top
  if (index === 0) {
    scrollBox.scrollTo(0);
    return;
  }

  // Last item — scroll to bottom
  if (index === list.length - 1) {
    scrollBox.scrollTo(Infinity);
    return;
  }

  // Scroll into view if outside the viewport
  const targetVisualY = target.y - scrollBox.y;
  const viewportHeight = scrollBox.height;
  const targetHeight = target.height || 1;

  if (targetVisualY + targetHeight > viewportHeight) {
    scrollBox.scrollBy(targetVisualY - viewportHeight + targetHeight + 1);
  } else if (targetVisualY < 0) {
    scrollBox.scrollBy(targetVisualY);
  }
}

function findChildById(
  scrollBox: ScrollBoxRenderable,
  id: string | undefined,
): Renderable | undefined {
  if (!id) return undefined;
  for (const group of scrollBox.getChildren()) {
    const found = group.getChildren().find((child) => child.id === id);
    if (found) return found;
  }
  return undefined;
}
