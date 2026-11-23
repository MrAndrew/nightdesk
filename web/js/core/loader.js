// Shared loading indicator: the Night Desk brand mark (the lamplight cone) in motion — the cone
// sweeps and a find-dot tracks under it, reading as "scanning". Styles + keyframes live in
// web/css/app.css (.nd-load / .nd-scan). Honours prefers-reduced-motion there. okf/architecture/web-client.md.
export const scanLoader = (label = 'Loading…') => `
  <div class="nd-load">
    <svg class="nd-scan" viewBox="0 0 32 32" aria-hidden="true">
      <rect x="11" y="4" width="10" height="3" rx="1.5"/>
      <g class="nd-scan-cone">
        <path class="nd-scan-beam" d="M12 7 H20 L25 23 H7 Z"/>
        <path class="nd-scan-edge" d="M12 7 H20 L25 23 H7 Z"/>
      </g>
      <path class="nd-scan-desk" d="M6 23 H26"/>
      <circle class="nd-scan-dot" cx="16" cy="19" r="2.3"/>
    </svg>
    ${label ? `<span class="nd-load-t">${label}</span>` : ''}
  </div>`;
