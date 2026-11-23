// The ⌘K command registry. Any module can add a command without touching this file:
//   import { registerCommand } from '../core/commands.js';
//   registerCommand({ id: 'notes.new', label: 'New note…', group: 'Notes', keywords: 'write', run: () => … });
// id: unique (registering the same id again replaces it). label: what the user reads. run(): what it does.
// Optional: group (a heading), keywords (extra words to match), order (lower first), when() (shown only if true).
// ⌘K / Ctrl+K itself opens the global search box in command mode (core/search.js), which lists these commands
// first and the search results after them: one result model for / and ⌘K.
// Contract: okf/architecture/web-client.md#command-palette
const COMMANDS = new Map();

export function registerCommand(cmd) {
  if (!cmd || !cmd.id || typeof cmd.run !== 'function') throw new Error('registerCommand needs {id, label, run}');
  COMMANDS.set(cmd.id, { order: 50, group: '', keywords: '', ...cmd });
}
export const commands = () => [...COMMANDS.values()];

// For callers that want "the palette" (Help's actions): the global search box in command mode.
export async function openPalette(prefill = '') {
  (await import('./search.js')).openCommandSearch(prefill);
}
