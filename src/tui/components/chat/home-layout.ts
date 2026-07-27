export interface HomeLayout {
  inputPadding: number;
  inputWidth: number;
  maxVisibleSuggestions: number;
  patternHeight: number;
  showSubtitle: boolean;
  showWorkflowHints: boolean;
  verticalGap: number;
}

export function getHomeLayout(width: number, height: number): HomeLayout {
  const horizontalInset = width >= 48 ? 4 : 2;
  const inputWidth = Math.max(1, Math.min(76, width - horizontalInset));
  const showSubtitle = height >= 16;
  const showWorkflowHints = height >= 20 && width >= 50;
  const inputPadding = height >= 18 ? 1 : 0;
  const verticalGap = height >= 24 ? 2 : 1;
  const patternHeight =
    height < 15
      ? 0
      : height < 20
        ? 2
        : height < 30
          ? Math.max(3, Math.floor(height * 0.15))
          : Math.max(6, Math.floor(height * 0.2));

  const fixedRows =
    patternHeight +
    (showSubtitle ? 2 : 1) +
    (showWorkflowHints ? 2 + verticalGap : 0) +
    inputPadding * 2 +
    4 +
    2;

  const available = Math.max(0, height - fixedRows);
  const maxSuggestions = height >= 40 ? 8 : 4;

  return {
    inputPadding,
    inputWidth,
    maxVisibleSuggestions: Math.max(2, Math.min(maxSuggestions, available)),
    patternHeight,
    showSubtitle,
    showWorkflowHints,
    verticalGap,
  };
}
