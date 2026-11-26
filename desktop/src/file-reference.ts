export function fileReference(value: string, link = false) {
  let path = value.trim();
  if (/^file:\/\//i.test(path)) {
    try {
      const url = new URL(path);
      if (url.hostname && url.hostname !== "localhost") return;
      path = decodeURIComponent(url.pathname);
      if (/^\/[a-z]:\//i.test(path)) path = path.slice(1);
    } catch {
      return;
    }
  } else {
    if (link) {
      try {
        path = decodeURIComponent(path);
      } catch {
        return;
      }
    }
  }
  path = path.replace(/(?::\d+(?::\d+)?|#L\d+(?:-L\d+)?)$/, "");
  if (
    path.startsWith("#") ||
    (/^[a-z][\w+.-]*:/i.test(path) && !/^[a-z]:[\\/]/i.test(path))
  )
    return;
  if (
    !path ||
    [...path].some((char) => char.charCodeAt(0) < 32) ||
    /[<>|?*]/.test(path) ||
    path.startsWith("//")
  )
    return;
  const name = path.split(/[\\/]/).at(-1);
  if (
    !name ||
    !/(?:\.[a-z][\w-]*|^(?:Dockerfile|Makefile|README|LICENSE))$/i.test(name)
  )
    return;
  return { path, name };
}
