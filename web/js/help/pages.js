// "On this page": what each view (and sub-page) is for, what its parts mean, and the common tasks there with an
// action that does the step. Content only; pageFor(hash) picks the entry for where the reader is.
// A task: { label, text, act } (actions: help/actions.js). Parts: [name, plain explanation].
// Contract: okf/architecture/help.md#on-this-page
import { shownTasks } from './actions.js';

export const PAGES = {
  watch: {
    title: 'Watch',
    lede: 'Your morning page: is my network touching anything bad, does a newly exploited bug or story affect me, and what else happened since I last looked.',
    parts: [
      ['Since …', 'Everything here is new since you last pressed Caught up (at most 7 days back). The first visit shows the last 24 hours.'],
      ['Your network', 'Incidents that need you, newest first, and how current your logs are. Demo incidents show only when there are no real ones.'],
      ['Touches you', 'Exploited bugs your logs mention, stories naming addresses in your alerts, and new KEV entries for things you follow.'],
      ['Newly exploited', 'New entries on CISA\'s exploited list (KEV), most likely to be attacked first (EPSS).'],
      ['News you follow, Big stories', 'Your watchlist digest, then stories covered by several outlets.'],
      ['Source health', 'Shows only when something is wrong: offline mode, a failing source, or one Watch needs turned off.'],
      ['Get set up', 'The setup checklist on a new install. Hide it any time; the masthead link brings it back.'],
    ],
    tasks: [
      { label: 'Load demo data', text: 'See what Night Desk finds on a made-up home network.', act: { api: '/api/netlog/demo', method: 'POST', then: '#network/alerts', done: 'Demo data loaded' } },
      { label: 'Follow a vendor', text: 'One click follows a vendor you run, so its news and exploited bugs show here.', act: { fn: 'follow' } },
      { label: 'Connect your logs', text: 'A firewall, a sensor, Pi-hole, or files.', act: { go: '#network/import' } },
      { label: 'Check everything is working', text: 'Sources, logs, the AI helper and offline mode, each with a fix.', act: { help: 'status' } },
    ],
    terms: ['marker', 'needs-you', 'kev', 'epss', 'watchlist'],
    guides: ['start', 'follow'],
  },

  'network/overview': {
    title: 'Network › Overview',
    lede: 'Your own network at a glance: what needs you, how current your logs are, and where your traffic goes.',
    parts: [
      ['N things need you', 'The one alert count: new, not expected, not demo, high or medium. Low and info are shown apart.'],
      ['Logs cover up to …', 'The newest log time, with a plain warning for each source that has gone quiet.'],
      ['Timeline', 'Connections, then alerts by severity. Drag across it to zoom every chart; Reset zoom goes back.'],
      ['Top talkers, countries, network owners, ports', 'Where your traffic goes. Click any value for a menu: search your logs for it, leave it out, open its device or look it up.'],
    ],
    tasks: [
      { label: 'Open what needs you', text: 'The worst open incident first.', act: { fn: 'first-alert' } },
      { label: 'Load demo data', text: 'No logs yet? Try a made-up network.', act: { api: '/api/netlog/demo', method: 'POST', done: 'Demo data loaded' } },
      { label: 'Connect your logs', text: 'Set up your firewall or sensor to send logs.', act: { go: '#network/import' } },
      { label: 'Change when logs count as stale', text: 'Default 24 hours.', act: { go: '#settings/home' } },
    ],
    terms: ['needs-you', 'freshness', 'asn', 'home-prefix'],
    guides: ['connect', 'investigate'],
  },

  'network/alerts': {
    title: 'Network › Alerts',
    lede: 'Every time a device of yours touched something on a threat list, grouped into incidents, worst first. Triage here.',
    parts: [
      ['The list', 'One row per incident: the device, a plain headline, severity, and chips for DEMO, Found later and status.'],
      ['Status filter', 'New, Acknowledged, Dismissed, Expected (hidden by your rules) or All. Severity chips filter too.'],
      ['View', 'Flat by default, or grouped by Device, Indicator or Rule (remembered).'],
      ['Detail', 'Why it has its severity, what to do, what happened, the listed-by chart, questions to ask, and the evidence chain.'],
      ['Expected traffic', 'Your rules that mark harmless repeats as normal. They hide alerts without deleting them.'],
    ],
    tasks: [
      { label: 'Open the top alert', text: 'The worst open incident.', act: { fn: 'first-alert' } },
      { label: 'Add an expected-traffic rule', text: 'Open an alert and choose "This is expected…". Its rule list is here.', act: { fn: 'first-alert', then: 'expect' } },
      { label: 'Review your rules', text: 'Edit or delete expected-traffic rules.', act: { go: '#network/alerts/rules' } },
      { label: 'Triage with the keyboard', text: 'j / k move, a acknowledges, d dismisses.', act: { help: 'keys' } },
      { label: 'Load demo data', text: 'See example alerts of every kind.', act: { api: '/api/netlog/demo', method: 'POST', done: 'Demo data loaded' } },
    ],
    terms: ['incident', 'severity', 'needs-you', 'expected-traffic', 'acknowledge', 'found-later', 'c2'],
    guides: ['investigate', 'quiet'],
  },

  'network/alert': {
    title: 'An alert',
    lede: 'One incident in full: what your device did, why it matters, and what to do about it.',
    parts: [
      ['Headline and Why …', 'Who started the contact, which list named the address and how far that list is trusted, and anything that lowered the severity (a DNS filter blocked it, file sharing, an unclear direction).'],
      ['What to do', 'Steps for this kind of alert. "Already blocked" alerts skip the block step.'],
      ['Listed by … chart', 'When the list named the address (while listed, not listed) against when your device touched it.'],
      ['Questions', 'Ready-made checks: did anything else talk to it, did the device do anything unusual around then.'],
      ['Evidence chain', 'The exact log rows behind the alert, with the raw record.'],
      ['This is expected…', 'Make a rule so harmless repeats stop needing you.'],
      ['Notes and Copy summary', 'Your own notes on the incident, and a Markdown summary to paste elsewhere with your devices and addresses replaced.'],
    ],
    tasks: [
      { label: 'See everything the device did', text: 'Search its logs.', act: { go: '#network/hunt' } },
      { label: 'Mark it as expected', text: 'Scroll to "This is expected…" in the detail.', act: { fn: 'expect' } },
      { label: 'Acknowledge or dismiss', text: 'Press a or d, or use the buttons at the top.', act: { help: 'keys' } },
      { label: 'Save a note, copy a summary', text: 'Notes sit above the Questions; Copy summary is in the action row, with your network redacted.', act: { help: 'guides/investigate' } },
    ],
    terms: ['severity', 'direction', 'trust-tier', 'found-later', 'before-listing', 'historical', 'sinkhole', 'p2p', 'note', 'copy-summary'],
    guides: ['investigate', 'quiet'],
  },

  'network/rules': {
    title: 'Network › Expected traffic',
    lede: 'Your rules for traffic that is normal on your network. Matching alerts are kept, listed as Expected, and never need you.',
    parts: [
      ['Scope', 'This device + this address, any device + this address, or this device + one kind of alert.'],
      ['Note and end', 'Why you made it, and an optional end date after which the traffic alerts again.'],
      ['Delete', 'Brings the hidden alerts back at once.'],
    ],
    tasks: [
      { label: 'Add a rule from an alert', text: 'Rules are made from the alert they quiet.', act: { fn: 'first-alert' } },
    ],
    terms: ['expected-traffic', 'incident'],
    guides: ['quiet'],
  },

  'network/hunt': {
    title: 'Network › Search logs',
    lede: 'Search your raw logs: everything a device, address or name did, beyond what raised an alert.',
    parts: [
      ['Query bar', 'Chips you can remove: ip:198.51.100.7, -port:443, log_type:dns, device:…, raw.<field>:…, or free text.'],
      ['Presets', 'Ready-made searches such as old TLS, remote-access sessions or big uploads.'],
      ['Histogram', 'Rows over time split by log type; drag to zoom.'],
      ['Group by', 'Count by any field (or two): device, hour, day, raw fields.'],
      ['Rows', 'Click a row for its raw log record.'],
    ],
    tasks: [
      { label: 'Search logs for one address', text: 'Everything your network did with one address, range or name.', act: { fn: 'hunt', label: 'Search logs…' } },
      { label: 'Load demo data', text: 'Nothing to search yet?', act: { api: '/api/netlog/demo', method: 'POST', done: 'Demo data loaded' } },
    ],
    terms: ['hunt', 'dns', 'sni', 'cidr', 'zeek'],
    guides: ['investigate'],
  },

  'network/devices': {
    title: 'Network › Devices',
    lede: 'Every device in your logs, how sure Night Desk is about who is who, and what each one talks to.',
    parts: [
      ['Name', 'Your label first, then a name from the logs, then "Unnamed device" with a hint (maker, type).'],
      ['Identity', 'certain (DHCP), derived (from an IPv6 address), probable (same names) or IP only.'],
      ['Unidentified', 'Rotating IPv6 addresses that nothing ties to a device, folded together.'],
      ['Detail', 'First and last seen, activity by hour, hostnames, alerts, top destinations and lookups. Name it, give it a type and owner, or merge it with another record.'],
    ],
    tasks: [
      { label: 'Name your devices', text: 'Opens the rename form on the first unnamed device; every alert then uses its name.', act: { fn: 'name-device', label: 'Name one' } },
      { label: 'Get told about new devices', text: 'On by default after a learning week; switch it in Connect logs › Home network.', act: { go: '#network/import' } },
    ],
    terms: ['device-identity', 'mac', 'private-mac', 'eui64', 'fragment', 'new-device'],
    guides: ['connect'],
  },

  'network/import': {
    title: 'Network › Connect logs',
    lede: 'Get your network\'s logs into Night Desk: a guided setup for your firewall or sensor, plain file import, the demo, and your own lists.',
    parts: [
      ['What do you have?', 'OPNsense, pfSense, Security Onion, a Zeek or Suricata sensor, Pi-hole, AdGuard Home, or just files. Each gets its own steps.'],
      ['Waiting for the first check-in', 'Amber until the device checks in, green once its first logs arrive.'],
      ['Imported files', 'Each file\'s log types, rows, duplicates, rejected lines and matches.'],
      ['Demo', 'Load or remove the made-up network.'],
      ['Home network', 'Your home prefixes, and whether to be told when a new device joins (after a learning period).'],
      ['Your own lists', 'Upload addresses, ranges or domains you consider bad; every imported log is re-checked.'],
      ['Advanced: device uploads', 'The upload port, every device token and recent uploads.'],
    ],
    tasks: [
      { label: 'Connect a firewall or sensor', text: 'Step by step, with the commands to run.', act: { help: 'guides/connect' } },
      { label: 'Load demo data', text: 'A made-up home with planted threats.', act: { api: '/api/netlog/demo', method: 'POST', then: '#network/alerts', done: 'Demo data loaded' } },
      { label: 'Set your home prefixes', text: 'So directions are right.', act: { go: '#settings/home' } },
    ],
    terms: ['zeek', 'suricata', 'eve', 'sinkhole', 'push-upload', 'own-list', 'home-prefix', 'new-device', 'demo'],
    guides: ['connect', 'start'],
  },

  news: {
    title: 'News',
    lede: 'Security news from outlets and research teams, grouped into stories, with what you follow first.',
    parts: [
      ['Rail', 'Views (all, new since your last visit, covered by several outlets, your watchlist), the watchlist itself, trust tiers and outlets.'],
      ['Stream', 'Story cards by day: how many outlets, NEW badges, the headline, a summary, and chips for the groups, malware, CVEs and indicators named.'],
      ['Story', 'Summary with citations, victims, a coverage timeline, actors and malware with confidence, indicators with exports, techniques, CVEs and similar stories.'],
      ['Article', 'What was extracted first (names, indicators, techniques, CVEs), then the text with highlights.'],
    ],
    tasks: [
      { label: 'Follow a vendor', text: 'Add it to your watchlist in one click.', act: { fn: 'follow' } },
      { label: 'Mark all as read', text: 'Moves your "last seen" time to now, the same as Caught up on Watch.', act: { fn: 'caught-up', label: 'Mark all as read' } },
      { label: 'Search the news', text: 'Press / here to search news only.', act: { help: 'keys' } },
    ],
    terms: ['story', 'watchlist', 'trust-tier', 'ioc', 'attack-technique', 'stix', 'seen-on-network', 'marker'],
    guides: ['follow'],
  },
  'news/story': {
    title: 'A news story',
    lede: 'Everything the outlets said about one event, merged, with the indicators and techniques extracted and checked against your network.',
    parts: [
      ['Summary', 'Numbered citations point to the articles. AI marks a summary written by the local helper.'],
      ['Actors and malware', 'With their claimed relationships and confidence.'],
      ['Indicators', 'Addresses, domains and hashes named, each with "Seen on your network" when it was. Export STIX 2.1, MISP or CSV.'],
      ['Techniques', 'Read automatically from the text and can be wrong: Named in the article, Likely, or Possible (faint, not exported). Click or tap one to see its sentence.'],
      ['Notes and Copy summary', 'Your notes under the summary, and a Markdown summary of the story in its actions.'],
    ],
    tasks: [
      { label: 'How to tell if it touches you', text: 'Look for amber or red "Seen on your network" chips in Indicators.', act: { help: 'glossary/seen-on-network' } },
    ],
    terms: ['story', 'ioc', 'confidence', 'attack-technique', 'stix', 'seen-on-network', 'trust-tier'],
    guides: ['entity'],
  },

  entities: {
    title: 'Intel',
    lede: 'Everything Night Desk knows about threat groups, malware, tools, campaigns, CVEs and indicators, with who said it.',
    parts: [
      ['Directory', 'Entities by type with mentions, claims, a trend line and the strongest claim\'s confidence. Placeholder names are hidden.'],
      ['Graph', 'Start from one entity and expand its links. Hypotheses and techniques are off until you switch them on.'],
      ['Review', 'Likely duplicates to merge, contested attributions, and the claims you disagreed with, each with Undo.'],
    ],
    tasks: [
      { label: 'Find an entity', text: 'Press / and type a name.', act: { fn: 'search' } },
      { label: 'Work through Review', text: 'Merge duplicates and settle contested attributions.', act: { go: '#entities/review' } },
      { label: 'Open the graph', text: 'See how things connect.', act: { go: '#entities/graph' } },
    ],
    terms: ['entity', 'threat-actor', 'claim', 'confidence', 'hypothesis', 'trust-tier'],
    guides: ['entity'],
  },
  'entities/page': {
    title: 'An entity page',
    lede: 'One group, malware, CVE or address: what it is, who says what about it, how sure to be, and whether it touched your network.',
    parts: [
      ['Summary', 'For an address: which lists name it and whether it was seen on your network. For a CVE: CVSS, EPSS, KEV, the fix and the deadline.'],
      ['Claims', 'Observed, Reported and Your links, each with a confidence band and its reason. Disagree… on anything a person can judge.'],
      ['Hypotheses', 'Links Night Desk worked out itself; hidden until you show them, never counted.'],
      ['ATT&CK techniques', 'The tactics strip: confirmed (MITRE ATT&CK or you) solid; named, likely and possible ones read from articles lighter, with their sentence on a click or tap.'],
      ['Indicators', 'Addresses, domains and hashes tied to it, with STIX 2.1 and CSV export.'],
      ['Touches your network', 'Matching alerts, devices and connections from your own logs.'],
      ['Notes and Copy summary', 'Your notes on the entity (side column) and a Markdown summary of it (header actions).'],
    ],
    tasks: [
      { label: 'How to disagree with a claim', text: 'Choose Disagree… on its row and give a reason; it can be undone.', act: { help: 'glossary/disagree' } },
      { label: 'Merge a duplicate', text: 'Use Same as… or the Review tab.', act: { go: '#entities/review' } },
    ],
    terms: ['claim', 'confidence', 'hypothesis', 'disagree', 'merge', 'trust-tier', 'seen-on-network', 'attack-technique', 'stix'],
    guides: ['entity'],
  },
  'entities/graph': {
    title: 'Intel › Graph',
    lede: 'How things connect, starting from one entity. Click a node to expand it.',
    parts: [
      ['Edges', 'Observed solid, reported dashed blue, your links amber, hypotheses dotted, seen on your network teal; thicker means more confident.'],
      ['Toolbar', 'Layouts, Fit, origin switches, Show hypotheses, minimum confidence and an "as of" time slider.'],
      ['Legend', 'Switch types on and off; techniques and tools start off.'],
    ],
    tasks: [
      { label: 'Find a starting point', text: 'Search for any entity and open its graph.', act: { fn: 'search' } },
    ],
    terms: ['hypothesis', 'confidence', 'claim', 'seen-on-network'],
    guides: ['entity'],
  },
  'entities/review': {
    title: 'Intel › Review',
    lede: 'A place to work through, with no count: likely duplicates, contested attributions, and the changes you made.',
    parts: [
      ['Likely duplicates', 'Keep either one, or say Not the same so it is not suggested again.'],
      ['Contested attributions', 'Sources name different groups; choose This one or Disagree….'],
      ['You disagreed', 'Each claim you rejected, with your reason and Undo.'],
      ['Your identity changes', 'Merges and type fixes, with Undo.'],
    ],
    tasks: [],
    terms: ['merge', 'disagree', 'claim', 'confidence'],
    guides: ['entity'],
  },

  ops: {
    title: 'Ops',
    lede: 'A wall of live widgets: the map, exploited bugs, news, outages, routing, Cyber Pulse and your own network.',
    parts: [
      ['Decks', 'Saved arrangements: Cyber Ops, Threat Infrastructure, Vulnerabilities, Internet Health, or your own.'],
      ['+ Widget', 'Add any panel from the catalogue; drag the title to move, the corner to resize.'],
      ['Time range', '1H to ALL, for the panels that follow it.'],
      ['Source health ›', 'The state of every source, in Settings › Sources.'],
    ],
    tasks: [
      { label: 'Add a widget', text: 'Press + Widget in the bar above the wall.', act: { fn: 'click', sel: '#add-widget' } },
      { label: 'Show it on a wall display', text: 'Cinema full screen.', act: { go: '#cinema?kiosk' } },
    ],
    terms: ['deck', 'pulse', 'pulse-subindex', 'kev', 'bgp', 'outage'],
    guides: ['follow'],
  },
  cinema: {
    title: 'Cinema',
    lede: 'A slow, cinematic globe that steps through real events, for a second screen.',
    parts: [
      ['Autopilot', 'Flies to each event in turn. Space pauses; arrows step.'],
      ['Ticker and HUD', 'The events in the tour and live routing activity.'],
      ['Full screen', 'Kiosk mode hides every bar; Esc leaves.'],
    ],
    tasks: [
      { label: 'Go full screen', text: 'For a wall display.', act: { go: '#cinema?kiosk' } },
    ],
    terms: ['kiosk', 'bgp'],
    guides: [],
  },
  explorer: {
    title: 'SQL console',
    lede: 'Ask your own questions of Night Desk\'s tables. Read-only: it cannot change or break anything.',
    parts: [
      ['Tables', 'The lake\'s own tables: events, netlog, alerts, devices, entities, claims and more.'],
      ['Query', 'One SELECT, WITH, PIVOT, DESCRIBE or SUMMARIZE at a time, with an 8-second limit. A PIVOT lists its values: ON kind IN (\'a\', \'b\'). ⌘↵ runs.'],
      ['Off by default', 'A power tool, so it is off unless Night Desk is started with OSINTHUB_SQL_CONSOLE=1. Settings › About says whether it is on.'],
    ],
    tasks: [
      { label: 'Read the safe-use guide', text: 'Examples and limits.', act: { help: 'guides/sql' } },
    ],
    terms: ['sql-console', 'lake'],
    guides: ['sql'],
  },

  notes: {
    title: 'Notes',
    lede: 'Every note you have written, on incidents, entities, stories and articles, in one place. Notes are kept on the Night Desk server, so they follow you to any device.',
    parts: [
      ['The list', 'Notes grouped by the item they are on, newest change first. Each item title links back to it.'],
      ['Search and filter', 'Search the notes and the item titles, or show one kind: incidents, entities, stories or articles.'],
      ['Writing notes', 'Add, edit (Ctrl+Enter saves, Esc cancels) and delete notes where the item is shown. Simple formatting works: **bold**, *italic*, `code`, lists and links.'],
      ['Badges', 'A small count on alert rows, story cards and entity rows shows where notes exist.'],
    ],
    tasks: [
      { label: 'Write a note on an alert', text: 'Open an incident; its notes sit above the Questions.', act: { fn: 'first-alert' } },
      { label: 'Share an alert safely', text: 'Copy summary gives clean Markdown with your network redacted.', act: { help: 'glossary/copy-summary' } },
    ],
    terms: ['note', 'copy-summary', 'incident', 'entity'],
    guides: ['investigate'],
  },

  settings: {
    title: 'Settings',
    lede: 'What Night Desk fetches, what it keeps and how it looks. Everything here stays on this machine.',
    parts: [
      ['Sources', 'Every source with its terms, on or off, and the local pipeline (AI helper, vector index, fetch queue).'],
      ['Home network', 'Home prefixes, when logs count as stale, upload silence thresholds.'],
      ['Data and retention', 'Where the data folder is, how big it is, and how long to keep data.'],
      ['Display', 'The page Night Desk opens on.'],
      ['About', 'Version, data folder, offline mode and the AI helper.'],
    ],
    tasks: [
      { label: 'Review every source\'s terms', text: 'In plain words, with links.', act: { help: 'sources' } },
      { label: 'Copy diagnostics', text: 'A redacted summary to paste into a bug report.', act: { fn: 'copy-diag', label: 'Copy' } },
    ],
    terms: ['lake', 'offline-mode', 'ai-helper', 'home-prefix'],
    guides: ['backup', 'offline'],
  },
  'settings/sources': {
    title: 'Settings › Sources',
    lede: 'Every source Night Desk can read: what it gives, its terms, whether it is on, and how it is doing.',
    parts: [
      ['Choose your sources', 'On a new install, open-terms sources start ticked and the rest are your call.'],
      ['Every source', 'Turn sources on or off, run one now, and see its last run and items.'],
      ['Behind the scenes', 'The optional AI helper, the search index, the article fetch queue, Intel and log matching, under Technical details.'],
    ],
    tasks: [
      { label: 'Read the terms in plain words', text: 'Every source and dataset, with credits.', act: { help: 'sources' } },
      { label: 'Add the free abuse.ch key', text: 'Add your free abuse.ch key to unlock ThreatFox and URLhaus: Settings › Sources says where it goes for your install.', act: { go: '#settings/sources', label: 'Open Sources' } },
    ],
    terms: ['threat-list', 'trust-tier', 'abusech', 'ai-helper', 'offline-mode'],
    guides: ['offline'],
  },
  'settings/home': {
    title: 'Settings › Home network',
    lede: 'Tell Night Desk which addresses are yours, and when quiet logs should worry you.',
    parts: [
      ['Home prefixes', 'Your address ranges, with suggestions from your logs. Saving re-checks recent logs.'],
      ['Stale after', 'How long without new logs before Night Desk warns (24 hours by default).'],
      ['Upload devices', 'Each device\'s own silence threshold.'],
    ],
    tasks: [
      { label: 'Review expected-traffic rules', text: 'The rules that mark normal traffic.', act: { go: '#network/alerts/rules' } },
    ],
    terms: ['home-prefix', 'freshness', 'push-upload', 'expected-traffic'],
    guides: ['connect'],
  },
  'settings/data': {
    title: 'Settings › Data and retention',
    lede: 'Where your data lives and how long it is kept.',
    parts: [
      ['Data folder', 'The lake: database, raw source records, reference data and uploads, with sizes.'],
      ['Retention', 'Off by default: everything is kept until you set a limit.'],
    ],
    tasks: [
      { label: 'Back up or move the data', text: 'Step by step.', act: { help: 'guides/backup' } },
    ],
    terms: ['lake'],
    guides: ['backup'],
  },
};
// tasks that depend on the app's state (only "Load demo data" today): read through help/actions.js shownTasks
for (const p of Object.values(PAGES)) {
  const all = p.tasks || [];
  Object.defineProperty(p, 'tasks', { get: () => shownTasks(all), enumerable: true });
}

// The page entry for a hash: '#network/alerts/nl-1' -> 'network/alert', '#entities/actor:x' -> 'entities/page'.
export function pageKey(hash) {
  const [v0 = '', a = '', b = ''] = String(hash || '').replace(/^#\/?/, '').split('?')[0].split('/').map((x) => decodeURIComponent(x || ''));
  const v = v0.toLowerCase();
  if (v === 'network') {
    if (a === 'alerts' && b === 'rules') return 'network/rules';
    if (a === 'alerts' && b) return 'network/alert';
    return `network/${['overview', 'alerts', 'hunt', 'devices', 'import'].includes(a) ? a : 'overview'}`;
  }
  if (v === 'news') return a === 'story' || a === 'article' ? 'news/story' : 'news';
  if (v === 'entities' || v === 'intel') {
    if (!a || a === 'metro') return 'entities';
    if (a === 'graph' || a === 'review') return `entities/${a}`;
    return 'entities/page';
  }
  if (v === 'settings') return PAGES[`settings/${a}`] ? `settings/${a}` : 'settings';
  if (v === 'sources') return 'settings/sources';
  if (v === 'notes') return 'notes';
  return PAGES[v] ? v : 'watch';
}

// The order "Help for another page" lists them in.
export const PAGE_ORDER = ['watch', 'network/overview', 'network/alerts', 'network/alert', 'network/rules', 'network/hunt',
  'network/devices', 'network/import', 'news', 'news/story', 'entities', 'entities/page', 'entities/graph',
  'entities/review', 'notes', 'ops', 'cinema', 'explorer', 'settings', 'settings/sources', 'settings/home', 'settings/data'];
