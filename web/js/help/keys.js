// Keyboard shortcuts, as the code implements them. Each row names the file that handles it and a `probe`: a piece of
// that handler's code. tests/test_v11_help.py checks every probe is still in its file, so this list cannot drift
// from the real shortcuts. The ⌘K palette entries are not listed here: the Help desk reads them live from
// core/commands.js. Contract: okf/architecture/help.md#shortcuts
export const KEY_GROUPS = [
  { where: 'Anywhere', rows: [
    { keys: ['/'], label: 'Search everything (people, malware, CVEs, news, events)', src: 'web/js/core/shell.js', probe: "e.key === '/'" },
    { keys: ['⌘K', 'Ctrl+K'], label: 'Commands first, then search results: jump to any page or run an action', src: 'web/js/core/search.js', probe: "e.key.toLowerCase() === 'k'" },
    { keys: ['?'], label: 'Open this Help desk', src: 'web/js/core/help.js', probe: "e.key !== '?'" },
    { keys: ['Esc'], label: 'Close the open panel, drawer, menu or this desk (one layer at a time)', src: 'web/js/core/shell.js', probe: "e.key === 'Escape'" },
  ] },
  { where: 'Search box and command palette', rows: [
    { keys: ['↑', '↓'], label: 'Move through the results', src: 'web/js/core/search.js', probe: "e.key === 'ArrowDown'" },
    { keys: ['Enter'], label: 'Open the highlighted result', src: 'web/js/core/search.js', probe: "e.key === 'Enter'" },
    { keys: ['⌘Enter', 'Shift+Enter'], label: 'Open an entity\'s full page instead of the side panel', src: 'web/js/core/search.js', probe: 'shiftKey: e.shiftKey' },
  ] },
  { where: 'Network › Alerts', rows: [
    { keys: ['j', 'k'], label: 'Next / previous incident', src: 'web/js/views/net/alerts.js', probe: "e.key === 'j' || e.key === 'k'" },
    { keys: ['a'], label: 'Acknowledge the open incident', src: 'web/js/views/net/alerts.js', probe: "e.key === 'a'" },
    { keys: ['d'], label: 'Dismiss it', src: 'web/js/views/net/alerts.js', probe: "e.key === 'd'" },
  ] },
  { where: 'News', rows: [
    { keys: ['/'], label: 'Search the news (instead of everything)', src: 'web/js/views/news.js', probe: "e.key === '/'" },
    { keys: ['j', 'k'], label: 'Next / previous story', src: 'web/js/views/news.js', probe: "e.key === 'j' || e.key === 'k'" },
    { keys: ['Enter'], label: 'Open the focused story', src: 'web/js/views/news.js', probe: "e.key === 'Enter' || e.key === ' '" },
    { keys: ['Esc'], label: 'Close one layer: panel, rail, then the story', src: 'web/js/views/news.js', probe: "e.key === 'Escape'" },
  ] },
  { where: 'Cinema', rows: [
    { keys: ['←', '→'], label: 'Previous / next event', src: 'web/js/views/cinema.js', probe: "e.key === 'ArrowRight'" },
    { keys: ['Space'], label: 'Pause or resume the autopilot', src: 'web/js/views/cinema.js', probe: "e.key === ' '" },
    { keys: ['Esc'], label: 'Leave full-screen (kiosk) mode', src: 'web/js/core/shell.js', probe: 'leaveKiosk(); return;' },
  ] },
  { where: 'SQL console', rows: [
    { keys: ['⌘Enter', 'Ctrl+Enter'], label: 'Run the query', src: 'web/js/views/explorer.js', probe: "(e.metaKey || e.ctrlKey) && e.key === 'Enter'" },
  ] },
  { where: 'Guided tour', rows: [
    { keys: ['←', '→'], label: 'Previous / next step', src: 'web/js/core/tour.js', probe: "e.key === 'ArrowRight'" },
    { keys: ['Esc'], label: 'End the tour', src: 'web/js/core/tour.js', probe: "if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); end(" },
  ] },
  { where: 'This Help desk', rows: [
    { keys: ['/'], label: 'Search help', src: 'web/js/help/desk.js', probe: "e.key === '/'" },
    { keys: ['↓'], label: 'From the search box, move into the results', src: 'web/js/help/desk.js', probe: "e.key === 'ArrowDown'" },
    { keys: ['Esc'], label: 'Close Help and return to where you were', src: 'web/js/help/desk.js', probe: "e.key === 'Escape'" },
  ] },
];
