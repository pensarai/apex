import { Renderable, ScrollBoxRenderable } from "@opentui/core";

/**
 * Scrolls a ScrollBox to keep the item at `index` visible.
 * Searches for the target element by ID among direct children
 * and one level of nesting (e.g., date-grouped lists).
 */
export function scrollToIndex<T>(
  scrollBox: ScrollBoxRenderable | null,
  index: number,
  list: T[],
  getId: (item: T) => string,
) {
  if (!scrollBox || list.length === 0) return;

  const item = list[index];
  if (!item) return;

  const target = findChildById(scrollBox, getId(item));
  if (!target) return;

  if (index === 0) {
    scrollBox.scrollTo(0);
    return;
  }

  if (index === list.length - 1) {
    scrollBox.scrollTo(Infinity);
    return;
  }

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
  id: string,
): Renderable | undefined {
  const direct = scrollBox.getChildren().find((child) => child.id === id);
  if (direct) return direct;

  for (const group of scrollBox.getChildren()) {
    const found = group.getChildren().find((child) => child.id === id);
    if (found) return found;
  }
  return undefined;
}
