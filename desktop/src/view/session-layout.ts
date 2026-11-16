export interface SessionLayout {
  order: string[];
  primary?: string;
  secondary?: string;
  focused?: string;
}

export type SessionLayoutAction =
  | { type: "open"; id: string }
  | { type: "select"; id: string }
  | { type: "dock"; id: string; side: "left" | "right"; beside?: string }
  | { type: "reorder"; id: string; target: string; after?: boolean }
  | { type: "close"; id: string }
  | { type: "single" };

export function sessionLayout(
  state: SessionLayout,
  action: SessionLayoutAction,
): SessionLayout {
  if (action.type === "open") {
    const order = state.order.includes(action.id)
      ? state.order
      : [...state.order, action.id];
    return sessionLayout(
      { ...state, order },
      { type: "select", id: action.id },
    );
  }
  if (action.type === "single")
    return { ...state, primary: state.focused, secondary: undefined };
  if (!state.order.includes(action.id)) return state;
  if (action.type === "select") {
    if (state.focused === action.id) return state;
    if (action.id === state.primary || action.id === state.secondary)
      return { ...state, focused: action.id };
    return {
      ...state,
      ...(state.secondary && state.focused === state.secondary
        ? { secondary: action.id }
        : { primary: action.id }),
      focused: action.id,
    };
  }
  if (action.type === "reorder") {
    if (action.id === action.target || !state.order.includes(action.target))
      return state;
    const order = state.order.filter((id) => id !== action.id);
    order.splice(
      order.indexOf(action.target) + Number(!!action.after),
      0,
      action.id,
    );
    return { ...state, order };
  }
  if (action.type === "dock") {
    const opposite = action.side === "left" ? state.secondary : state.primary;
    const other = [
      action.beside,
      opposite,
      state.primary,
      state.secondary,
      ...state.order,
    ].find((id) => id && id !== action.id && state.order.includes(id));
    if (!other) return { ...state, primary: action.id, focused: action.id };
    return {
      ...state,
      primary: action.side === "left" ? action.id : other,
      secondary: action.side === "right" ? action.id : other,
      focused: action.id,
    };
  }
  const order = state.order.filter((id) => id !== action.id);
  let { primary, secondary, focused } = state;
  if (action.id === primary) {
    primary =
      secondary ??
      order[Math.min(state.order.indexOf(action.id), order.length - 1)];
    secondary = undefined;
  } else if (action.id === secondary) secondary = undefined;
  if (focused === action.id) focused = primary;
  return { order, primary, secondary, focused };
}
