# Pensar Message Labelling Tool

A Next.js application for labelling and editing Pensar execution messages.

## Overview

This tool allows you to view, edit, and label messages from Pensar execution sessions. It provides an intuitive interface for modifying conversation history, tool calls, and message metadata.

## Features

- **Session Selection**: Browse and select from available Pensar execution sessions
- **Message File Selection**: Choose from main session messages or subagent messages
- **Visual Message Editor**: 
  - Color-coded by role (user, assistant, tool)
  - Edit all message fields inline
  - Rearrange messages with up/down controls
  - Delete messages
  - Add new messages
- **Tool Message Support**: Full editing support for tool-specific fields (toolName, status, toolCallId, args)
- **Change Tracking**: Visual indicator for unsaved changes
- **Manual Save**: Explicit save button (no auto-save)

## Getting Started

1. Install dependencies:
```bash
npm install
# or
bun install
```

2. Run the development server:
```bash
npm run dev
# or
bun dev
```

3. Open [http://localhost:3000](http://localhost:3000) in your browser

## Usage

1. **Select a Session**: On the home page, you'll see a list of available Pensar execution sessions from `~/.pensar/executions/`
2. **Select a Messages File**: After choosing a session, select which messages.json file to edit (main session or subagents)
3. **Edit Messages**: 
   - Click "Edit" on any message to modify its fields
   - Use ↑↓ buttons to reorder messages
   - Click "Delete" to remove messages
   - Click "Add Message" to create new messages
4. **Save Changes**: Click "Save Changes" when ready to persist your edits

## Message Structure

Messages can have the following fields:

### Common Fields (all roles)
- `role`: "user" | "assistant" | "tool"
- `content`: Message content/text
- `createdAt`: ISO timestamp

### Tool-specific Fields
- `toolName`: Name of the tool being called
- `status`: Tool execution status
- `toolCallId`: Unique identifier for the tool call
- `args`: JSON object containing tool arguments

## File Structure

- `app/page.tsx` - Home page with session list
- `app/[session]/page.tsx` - Session page that loads messages files
- `app/[session]/labelling.tsx` - Main labelling component
- `app/[session]/actions.ts` - Server actions for reading/writing files
- `components/session-list.tsx` - Session list component

## Development

This project uses:
- Next.js 16 (App Router)
- React 19
- TypeScript
- Tailwind CSS

## Notes

- Messages are stored in `~/.pensar/executions/[session-id]/messages.json`
- Subagent messages are in `~/.pensar/executions/[session-id]/subagents/[agent-id]/messages.json`
- Changes are only saved when you explicitly click "Save Changes"
- The editor validates JSON for tool arguments but allows partial edits
