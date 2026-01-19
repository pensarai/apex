/**
 * Input Buffer
 *
 * Manages text input state including cursor position and selection.
 * Provides undo/redo functionality and vim-like operations.
 */

export interface Selection {
  start: number;
  end: number;
}

export interface InputState {
  text: string;
  cursor: number;
  selection: Selection | null;
}

export interface UndoEntry {
  state: InputState;
  timestamp: number;
}

/**
 * Input Buffer class for managing text state
 */
export class InputBuffer {
  private text: string;
  private cursor: number;
  private selection: Selection | null;
  private undoStack: UndoEntry[];
  private redoStack: UndoEntry[];
  private clipboard: string;
  private maxUndoHistory: number;

  constructor(initialText: string = "", maxUndoHistory: number = 100) {
    this.text = initialText;
    this.cursor = initialText.length;
    this.selection = null;
    this.undoStack = [];
    this.redoStack = [];
    this.clipboard = "";
    this.maxUndoHistory = maxUndoHistory;

    // Save initial state
    this.saveUndo();
  }

  // ============================================
  // Getters
  // ============================================

  getText(): string {
    return this.text;
  }

  getCursor(): number {
    return this.cursor;
  }

  getSelection(): Selection | null {
    return this.selection;
  }

  getState(): InputState {
    return {
      text: this.text,
      cursor: this.cursor,
      selection: this.selection,
    };
  }

  getSelectedText(): string {
    if (!this.selection) return "";
    const { start, end } = this.normalizeSelection(this.selection);
    return this.text.slice(start, end);
  }

  // ============================================
  // State Management
  // ============================================

  private saveUndo(): void {
    this.undoStack.push({
      state: { ...this.getState() },
      timestamp: Date.now(),
    });
    // Limit undo history
    if (this.undoStack.length > this.maxUndoHistory) {
      this.undoStack.shift();
    }
    // Clear redo stack on new action
    this.redoStack = [];
  }

  undo(): boolean {
    if (this.undoStack.length <= 1) return false;

    // Move current state to redo stack
    const current = this.undoStack.pop()!;
    this.redoStack.push(current);

    // Restore previous state
    const prev = this.undoStack[this.undoStack.length - 1];
    if (prev) {
      this.text = prev.state.text;
      this.cursor = prev.state.cursor;
      this.selection = prev.state.selection;
      return true;
    }
    return false;
  }

  redo(): boolean {
    if (this.redoStack.length === 0) return false;

    const entry = this.redoStack.pop()!;
    this.undoStack.push(entry);
    this.text = entry.state.text;
    this.cursor = entry.state.cursor;
    this.selection = entry.state.selection;
    return true;
  }

  // ============================================
  // Text Manipulation
  // ============================================

  setText(text: string): void {
    this.saveUndo();
    this.text = text;
    this.cursor = Math.min(this.cursor, text.length);
    this.selection = null;
  }

  insert(str: string): void {
    this.saveUndo();

    if (this.selection) {
      // Replace selection with inserted text
      const { start, end } = this.normalizeSelection(this.selection);
      this.text = this.text.slice(0, start) + str + this.text.slice(end);
      this.cursor = start + str.length;
      this.selection = null;
    } else {
      // Insert at cursor
      this.text =
        this.text.slice(0, this.cursor) + str + this.text.slice(this.cursor);
      this.cursor += str.length;
    }
  }

  delete(count: number = 1): string {
    this.saveUndo();

    if (this.selection) {
      // Delete selection
      const { start, end } = this.normalizeSelection(this.selection);
      const deleted = this.text.slice(start, end);
      this.text = this.text.slice(0, start) + this.text.slice(end);
      this.cursor = start;
      this.selection = null;
      return deleted;
    } else {
      // Delete forward
      const deleted = this.text.slice(this.cursor, this.cursor + count);
      this.text =
        this.text.slice(0, this.cursor) + this.text.slice(this.cursor + count);
      return deleted;
    }
  }

  backspace(count: number = 1): string {
    this.saveUndo();

    if (this.selection) {
      return this.delete();
    } else {
      // Delete backward
      const start = Math.max(0, this.cursor - count);
      const deleted = this.text.slice(start, this.cursor);
      this.text = this.text.slice(0, start) + this.text.slice(this.cursor);
      this.cursor = start;
      return deleted;
    }
  }

  // ============================================
  // Cursor Movement
  // ============================================

  moveCursor(position: number, selecting: boolean = false): void {
    const newPosition = Math.max(0, Math.min(position, this.text.length));

    if (selecting) {
      if (!this.selection) {
        this.selection = { start: this.cursor, end: newPosition };
      } else {
        this.selection.end = newPosition;
      }
    } else {
      this.selection = null;
    }

    this.cursor = newPosition;
  }

  moveLeft(selecting: boolean = false): void {
    this.moveCursor(this.cursor - 1, selecting);
  }

  moveRight(selecting: boolean = false): void {
    this.moveCursor(this.cursor + 1, selecting);
  }

  moveToStart(selecting: boolean = false): void {
    this.moveCursor(0, selecting);
  }

  moveToEnd(selecting: boolean = false): void {
    this.moveCursor(this.text.length, selecting);
  }

  // ============================================
  // Word Operations
  // ============================================

  moveWordLeft(selecting: boolean = false): void {
    let pos = this.cursor;

    // Skip any whitespace to the left
    while (pos > 0 && /\s/.test(this.text[pos - 1])) {
      pos--;
    }

    // Move to start of word
    while (pos > 0 && !/\s/.test(this.text[pos - 1])) {
      pos--;
    }

    this.moveCursor(pos, selecting);
  }

  moveWordRight(selecting: boolean = false): void {
    let pos = this.cursor;

    // Skip any non-whitespace to the right
    while (pos < this.text.length && !/\s/.test(this.text[pos])) {
      pos++;
    }

    // Skip whitespace
    while (pos < this.text.length && /\s/.test(this.text[pos])) {
      pos++;
    }

    this.moveCursor(pos, selecting);
  }

  deleteWord(): string {
    this.saveUndo();

    const startPos = this.cursor;
    this.moveWordRight();
    const endPos = this.cursor;
    const deleted = this.text.slice(startPos, endPos);
    this.text = this.text.slice(0, startPos) + this.text.slice(endPos);
    this.cursor = startPos;
    return deleted;
  }

  deleteWordBackward(): string {
    this.saveUndo();

    const endPos = this.cursor;
    this.moveWordLeft();
    const startPos = this.cursor;
    const deleted = this.text.slice(startPos, endPos);
    this.text = this.text.slice(0, startPos) + this.text.slice(endPos);
    return deleted;
  }

  // ============================================
  // Selection
  // ============================================

  selectAll(): void {
    this.selection = { start: 0, end: this.text.length };
    this.cursor = this.text.length;
  }

  selectWord(): void {
    // Find word boundaries around cursor
    let start = this.cursor;
    let end = this.cursor;

    // Move start to beginning of word
    while (start > 0 && !/\s/.test(this.text[start - 1])) {
      start--;
    }

    // Move end to end of word
    while (end < this.text.length && !/\s/.test(this.text[end])) {
      end++;
    }

    if (start !== end) {
      this.selection = { start, end };
      this.cursor = end;
    }
  }

  clearSelection(): void {
    this.selection = null;
  }

  private normalizeSelection(sel: Selection): { start: number; end: number } {
    return {
      start: Math.min(sel.start, sel.end),
      end: Math.max(sel.start, sel.end),
    };
  }

  // ============================================
  // Clipboard Operations
  // ============================================

  yank(): string {
    const text = this.getSelectedText();
    if (text) {
      this.clipboard = text;
    }
    return this.clipboard;
  }

  paste(): void {
    if (this.clipboard) {
      this.insert(this.clipboard);
    }
  }

  getClipboard(): string {
    return this.clipboard;
  }

  setClipboard(text: string): void {
    this.clipboard = text;
  }

  // ============================================
  // Line Operations
  // ============================================

  deleteToEnd(): string {
    this.saveUndo();
    const deleted = this.text.slice(this.cursor);
    this.text = this.text.slice(0, this.cursor);
    return deleted;
  }

  deleteToStart(): string {
    this.saveUndo();
    const deleted = this.text.slice(0, this.cursor);
    this.text = this.text.slice(this.cursor);
    this.cursor = 0;
    return deleted;
  }

  clear(): void {
    this.saveUndo();
    this.text = "";
    this.cursor = 0;
    this.selection = null;
  }
}

export default InputBuffer;
