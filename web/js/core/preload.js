// Desktop: the chart, map, grid and globe libraries once the page is idle, so they are there before a view asks
// (a phone loads only what the view on screen needs). A file, not an inline script: the Content-Security-Policy
// allows scripts from this server only (plus the hash of index.html's stale-code check). js/core/libs.js
import { preloadAll } from './libs.js';
import { isPhone } from './mobile.js';

if (!isPhone()) (window.requestIdleCallback || ((f) => setTimeout(f, 200)))(() => preloadAll(), { timeout: 1500 });
