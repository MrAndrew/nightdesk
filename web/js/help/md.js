// A small, safe Markdown renderer for the local docs shown in the Help desk (okf/*.md). Every piece of text is
// escaped first; only headings, paragraphs, lists, tables, code, emphasis and links are produced. Links to other
// docs pages open inside the desk (#help/docs/<path>); outside links open in a new tab; anything else is text.
import { esc } from '../core/util.js';

function inline(s, base) {
  let t = esc(s);
  t = t.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
  t = t.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  t = t.replace(/(^|[\s(])\*([^*\s][^*]*)\*/g, '$1<i>$2</i>');
  t = t.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, href) => {
    const raw = href.replace(/&amp;/g, '&');
    if (/^https?:\/\//i.test(raw)) return `<a href="${href}" target="_blank" rel="noopener noreferrer">${label}</a>`;
    if (/\.md(#.*)?$/.test(raw) && !/^[a-z]+:/i.test(raw)) {
      const path = resolve(base, raw.split('#')[0]);
      return path ? `<a href="#help/docs/${esc(path)}" data-doc="${esc(path)}">${label}</a>` : label;
    }
    return label;
  });
  t = t.replace(/&lt;a id=&quot;[^&]*&quot;&gt;&lt;\/a&gt;/g, '');
  return t;
}

// '/data/netlog.md' or '../data/netlog.md' or 'netlog.md' against the current page's folder.
function resolve(base, href) {
  const parts = href.startsWith('/') ? [] : (base || '').split('/').slice(0, -1);
  for (const seg of href.replace(/^\//, '').split('/')) {
    if (seg === '..') parts.pop(); else if (seg && seg !== '.') parts.push(seg);
  }
  const p = parts.join('/');
  return /^[A-Za-z0-9_\-/.]+\.md$/.test(p) && !p.includes('..') ? p : null;
}

export function render(md, base = '') {
  const lines = String(md || '').replace(/\r/g, '').split('\n');
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (/^```/.test(l)) {
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push(`<pre><code>${esc(buf.join('\n'))}</code></pre>`);
      continue;
    }
    const hm = l.match(/^(#{1,4})\s+(.*)$/);
    if (hm) { const n = Math.min(6, hm[1].length + 2); out.push(`<h${n}>${inline(hm[2], base)}</h${n}>`); i++; continue; }
    if (/^\|/.test(l)) {
      const rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) rows.push(lines[i++]);
      const cells = (r) => r.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      const body = rows.filter((r) => !/^\|[\s:|-]+\|?$/.test(r));
      const [head, ...rest] = body;
      out.push(`<div class="help-md-tbl"><table><thead><tr>${cells(head).map((c) => `<th>${inline(c, base)}</th>`).join('')}</tr></thead><tbody>${rest.map((r) => `<tr>${cells(r).map((c) => `<td>${inline(c, base)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      continue;
    }
    if (/^\s*([*-]|\d+\.)\s+/.test(l)) {
      const ordered = /^\s*\d+\./.test(l);
      const items = [];
      while (i < lines.length && (/^\s*([*-]|\d+\.)\s+/.test(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && items.length))) {
        const m = lines[i].match(/^(\s*)([*-]|\d+\.)\s+(.*)$/);
        if (m) items.push({ d: m[1].length >= 2 ? 1 : 0, t: m[3] });
        else items[items.length - 1].t += ` ${lines[i].trim()}`;
        i++;
      }
      const tag = ordered ? 'ol' : 'ul';
      out.push(`<${tag}>${items.map((it) => `<li${it.d ? ' class="sub"' : ''}>${inline(it.t, base)}</li>`).join('')}</${tag}>`);
      continue;
    }
    if (!l.trim()) { i++; continue; }
    const buf = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|```|\||\s*([*-]|\d+\.)\s+)/.test(lines[i])) buf.push(lines[i++]);
    out.push(`<p>${inline(buf.join(' '), base)}</p>`);
  }
  return out.join('\n');
}
