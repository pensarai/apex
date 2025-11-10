// Reads the selected Mmessages file
// Display the messages in a list with a decent UX
// Allow the user to rearrange messages, edit data, edit tool calls etc.
// Look at an example session in ~/.pensar/executions/testTHISONE/messages.json to understand the structure
// Make the messages display better than just plain JSON. Consider parsing each element in the message object into a field for easy editing / viewing.
// Enabled the user to save the changes to the messages file. Dont auto save though, only one save.

"use client";

import { useState, useEffect } from "react";
import { readMessagesFile, saveMessagesFile, type Message } from "./actions";

export default function Labelling({
  messagesFiles,
}: {
  messagesFiles: string[];
}) {
  const [selectedFile, setSelectedFile] = useState<string>("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [hasChanges, setHasChanges] = useState(false);

  // Load messages when file is selected
  useEffect(() => {
    if (selectedFile) {
      loadMessages();
    }
  }, [selectedFile]);

  const loadMessages = async () => {
    setLoading(true);
    try {
      const data = await readMessagesFile(selectedFile);
      if (data) {
        setMessages(data);
        setHasChanges(false);
      }
    } catch (error) {
      console.error("Failed to load messages:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!selectedFile) return;

    setSaving(true);
    try {
      const result = await saveMessagesFile(selectedFile, messages);
      if (result.success) {
        setHasChanges(false);
        alert("Messages saved successfully!");
      } else {
        alert(`Failed to save: ${result.error}`);
      }
    } catch (error) {
      console.error("Failed to save messages:", error);
      alert("Failed to save messages");
    } finally {
      setSaving(false);
    }
  };

  const updateMessage = (index: number, updates: Partial<Message>) => {
    const newMessages = [...messages];
    newMessages[index] = { ...newMessages[index], ...updates };
    setMessages(newMessages);
    setHasChanges(true);
  };

  const deleteMessage = (index: number) => {
    if (confirm("Are you sure you want to delete this message?")) {
      const newMessages = messages.filter((_, i) => i !== index);
      setMessages(newMessages);
      setHasChanges(true);
    }
  };

  const moveMessage = (index: number, direction: "up" | "down") => {
    if (
      (direction === "up" && index === 0) ||
      (direction === "down" && index === messages.length - 1)
    ) {
      return;
    }

    const newMessages = [...messages];
    const targetIndex = direction === "up" ? index - 1 : index + 1;
    [newMessages[index], newMessages[targetIndex]] = [
      newMessages[targetIndex],
      newMessages[index],
    ];
    setMessages(newMessages);
    setHasChanges(true);
  };

  const addMessage = () => {
    const newMessage: Message = {
      role: "user",
      content: "",
      createdAt: new Date().toISOString(),
    };
    setMessages([...messages, newMessage]);
    setHasChanges(true);
    setEditingIndex(messages.length);
  };

  return (
    <div className="flex flex-col flex-1 w-full overflow-hidden">
      <div className="shrink-0 w-full max-w-6xl mx-auto py-4 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold">Message Labelling Editor</h2>
          {hasChanges && (
            <span className="text-sm text-yellow-600 dark:text-yellow-400">
              Unsaved changes
            </span>
          )}
        </div>

        {/* File Selection */}
        <div className="space-y-2">
          <label className="block text-sm font-medium">
            Select Messages File
          </label>
          <select
            value={selectedFile}
            onChange={(e) => setSelectedFile(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 dark:border-gray-700 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
          >
            <option value="">-- Select a file --</option>
            {messagesFiles.map((file) => (
              <option key={file} value={file}>
                {file}
              </option>
            ))}
          </select>
        </div>

        {/* Action Bar */}
        {!loading && selectedFile && messages.length > 0 && (
          <div className="flex items-center justify-between pb-2 border-b border-gray-200 dark:border-gray-700">
            <div className="text-sm text-gray-600 dark:text-gray-400">
              {messages.length} message{messages.length !== 1 ? "s" : ""}
            </div>
            <div className="flex gap-2">
              <button
                onClick={addMessage}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium"
              >
                Add Message
              </button>
              <button
                onClick={handleSave}
                disabled={!hasChanges || saving}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-md text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {saving ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Scrollable Messages Area */}
      <div className="flex-1 overflow-y-auto w-full">
        <div className="w-full max-w-6xl mx-auto px-6 py-4">
          {/* Loading State */}
          {loading && (
            <div className="text-center py-8 text-gray-600 dark:text-gray-400">
              Loading messages...
            </div>
          )}

          {/* Messages List */}
          {!loading && selectedFile && messages.length > 0 && (
            <div className="space-y-4 pb-6">
              {messages.map((message, index) => (
                <MessageEditor
                  key={index}
                  message={message}
                  index={index}
                  isEditing={editingIndex === index}
                  onEdit={() => setEditingIndex(index)}
                  onSave={() => setEditingIndex(null)}
                  onUpdate={(updates) => updateMessage(index, updates)}
                  onDelete={() => deleteMessage(index)}
                  onMove={(direction) => moveMessage(index, direction)}
                  canMoveUp={index > 0}
                  canMoveDown={index < messages.length - 1}
                />
              ))}
            </div>
          )}

          {/* Empty State */}
          {!loading && selectedFile && messages.length === 0 && (
            <div className="text-center py-8 text-gray-600 dark:text-gray-400">
              No messages found in this file.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface MessageEditorProps {
  message: Message;
  index: number;
  isEditing: boolean;
  onEdit: () => void;
  onSave: () => void;
  onUpdate: (updates: Partial<Message>) => void;
  onDelete: () => void;
  onMove: (direction: "up" | "down") => void;
  canMoveUp: boolean;
  canMoveDown: boolean;
}

function MessageEditor({
  message,
  index,
  isEditing,
  onEdit,
  onSave,
  onUpdate,
  onDelete,
  onMove,
  canMoveUp,
  canMoveDown,
}: MessageEditorProps) {
  const roleColors = {
    user: "bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800",
    assistant:
      "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800",
    tool: "bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-800",
  };

  return (
    <div
      className={`border rounded-lg p-4 ${roleColors[message.role]} space-y-3`}
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-wide">
            {message.role}
          </span>
          <span className="text-xs text-gray-500 dark:text-gray-400">
            #{index + 1}
          </span>
          <span className="text-xs text-gray-500 dark:text-gray-400">
            {new Date(message.createdAt).toLocaleString()}
          </span>
        </div>

        <div className="flex items-center gap-1">
          {/* Move buttons */}
          <button
            onClick={() => onMove("up")}
            disabled={!canMoveUp}
            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded disabled:opacity-30"
            title="Move up"
          >
            ↑
          </button>
          <button
            onClick={() => onMove("down")}
            disabled={!canMoveDown}
            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded disabled:opacity-30"
            title="Move down"
          >
            ↓
          </button>

          {/* Edit/Save button */}
          <button
            onClick={isEditing ? onSave : onEdit}
            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded"
          >
            {isEditing ? "Done" : "Edit"}
          </button>

          {/* Delete button */}
          <button
            onClick={onDelete}
            className="px-2 py-1 text-xs bg-red-200 dark:bg-red-900 hover:bg-red-300 dark:hover:bg-red-800 rounded"
          >
            Delete
          </button>
        </div>
      </div>

      {/* Role selector */}
      {isEditing && (
        <div className="space-y-2">
          <label className="block text-xs font-medium">Role</label>
          <select
            value={message.role}
            onChange={(e) =>
              onUpdate({ role: e.target.value as Message["role"] })
            }
            className="w-full px-2 py-1 text-sm border rounded bg-white dark:bg-gray-800"
          >
            <option value="user">User</option>
            <option value="assistant">Assistant</option>
            <option value="tool">Tool</option>
          </select>
        </div>
      )}

      {/* Content */}
      <div className="space-y-2">
        <label className="block text-xs font-medium">Content</label>
        {isEditing ? (
          <textarea
            value={message.content}
            onChange={(e) => onUpdate({ content: e.target.value })}
            className="w-full px-3 py-2 text-sm border rounded bg-white dark:bg-gray-800 font-mono resize-y"
            rows={5}
          />
        ) : (
          <div className="text-sm whitespace-pre-wrap font-mono bg-white dark:bg-gray-800 p-3 rounded border max-h-96 overflow-y-auto wrap-break-word">
            {message.content || <em className="text-gray-400">Empty</em>}
          </div>
        )}
      </div>

      {/* Tool-specific fields */}
      {message.role === "tool" && (
        <>
          {/* Tool Name */}
          <div className="space-y-2">
            <label className="block text-xs font-medium">Tool Name</label>
            {isEditing ? (
              <input
                type="text"
                value={message.toolName || ""}
                onChange={(e) => onUpdate({ toolName: e.target.value })}
                className="w-full px-3 py-2 text-sm border rounded bg-white dark:bg-gray-800"
              />
            ) : (
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded border">
                {message.toolName || <em className="text-gray-400">None</em>}
              </div>
            )}
          </div>

          {/* Status */}
          <div className="space-y-2">
            <label className="block text-xs font-medium">Status</label>
            {isEditing ? (
              <input
                type="text"
                value={message.status || ""}
                onChange={(e) => onUpdate({ status: e.target.value })}
                className="w-full px-3 py-2 text-sm border rounded bg-white dark:bg-gray-800"
              />
            ) : (
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded border">
                {message.status || <em className="text-gray-400">None</em>}
              </div>
            )}
          </div>

          {/* Tool Call ID */}
          <div className="space-y-2">
            <label className="block text-xs font-medium">Tool Call ID</label>
            {isEditing ? (
              <input
                type="text"
                value={message.toolCallId || ""}
                onChange={(e) => onUpdate({ toolCallId: e.target.value })}
                className="w-full px-3 py-2 text-sm border rounded bg-white dark:bg-gray-800"
              />
            ) : (
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded border">
                {message.toolCallId || <em className="text-gray-400">None</em>}
              </div>
            )}
          </div>

          {/* Args */}
          <div className="space-y-2">
            <label className="block text-xs font-medium">Arguments</label>
            {isEditing ? (
              <textarea
                value={
                  message.args ? JSON.stringify(message.args, null, 2) : ""
                }
                onChange={(e) => {
                  try {
                    const parsed = e.target.value
                      ? JSON.parse(e.target.value)
                      : undefined;
                    onUpdate({ args: parsed });
                  } catch (err) {
                    // Invalid JSON, just update the text
                  }
                }}
                className="w-full px-3 py-2 text-sm border rounded bg-white dark:bg-gray-800 font-mono resize-y"
                rows={4}
                placeholder="JSON object"
              />
            ) : (
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded border max-h-64 overflow-auto">
                {message.args ? (
                  <pre className="whitespace-pre-wrap wrap-break-word">
                    {JSON.stringify(message.args, null, 2)}
                  </pre>
                ) : (
                  <em className="text-gray-400">None</em>
                )}
              </div>
            )}
          </div>
        </>
      )}

      {/* Created At */}
      {isEditing && (
        <div className="space-y-2">
          <label className="block text-xs font-medium">Created At</label>
          <input
            type="text"
            value={message.createdAt}
            onChange={(e) => onUpdate({ createdAt: e.target.value })}
            className="w-full px-3 py-2 text-sm border rounded bg-white dark:bg-gray-800 font-mono"
          />
        </div>
      )}
    </div>
  );
}
