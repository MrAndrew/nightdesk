// Every Settings section, one line each. A new section is a new file in this folder plus one line here.
// Each loads on its own, so one broken section never takes Settings down.
const MODULES = [
  './sources.js',
  './watchlist.js',
  './home.js',
  './data.js',
  './display.js',
  './ai.js',
  './notifications.js',
  './about.js',
];
await Promise.all(MODULES.map((m) => import(m).catch((e) => console.warn(`settings section ${m} not loaded:`, e.message))));
