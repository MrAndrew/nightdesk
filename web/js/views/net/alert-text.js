// Network → Alerts: plain-language text for every kind of alert (headline, what happened, what to do, why this
// severity). One place, so the list, the detail and the questions read the same. Kinds: okf/data/netlog.md#alert-kinds
import { S, esc, fmt, devName, durWords } from './common.js';
import * as T from '../../core/time.js';

// The demo card's names for the lists, used when the sources table is not loaded.
const SRC = {
  feodo_c2: 'Feodo Tracker', spamhaus_drop: 'Spamhaus DROP', et_compromised: 'Emerging Threats', blocklist_de: 'blocklist.de',
  cins_army: 'CINS Army', dshield_top: 'DShield', tor_exits: 'the Tor exit list', cisa_kev: 'CISA KEV', threatfox: 'ThreatFox',
  urlhaus: 'URLhaus', sslbl: 'SSL Blacklist', reported: 'news reports', suricata: 'Suricata',
};
// Your own lists (Network › Connect logs › Your own lists) are sources `own:<id>`; their names come with the alerts.
const OWN = new Map();
export const rememberList = (id, name) => { if (id && name) OWN.set(id, name); };
const isOwn = (id) => String(id || '').startsWith('own:');
export const srcName = (id) => (id === 'reported' ? 'news reports'
  : isOwn(id) ? (OWN.has(id) ? `your list '${OWN.get(id)}'` : 'your own list')
    : S.sources.get(id)?.name || SRC[id] || id || 'a threat list');
const TIER_WORDS = { A: 'an official source', B: 'an established research list', C: 'a community list', D: 'unverified reports', U: 'your own list' };

// What a listed category is, as a noun phrase.
const WHAT = {
  c2: 'a known botnet controller', drop: 'a network run by criminals', compromised: 'a known-compromised server',
  reputation: 'an address with a bad reputation', listed: 'an address on a threat list', attacker: 'a known attacker',
  scanner: 'a known internet scanner', tor: 'the Tor network', reported: 'an address named in threat reports',
  reported_corroborated: 'an address named in threat reports', reported_tor: 'a Tor relay named in threat reports',
  malware: 'known malware', own: 'an address on your own list',
};
// Short kind labels (chips, groups, rule scopes).
export const KIND_LABEL = {
  c2: 'Botnet controller', drop: 'Criminal network (DROP)', compromised: 'Compromised host', reputation: 'Bad reputation',
  listed: 'Threat list', attacker: 'Known attacker', scanner: 'Internet scanner', tor: 'Tor', reported: 'Named in reports',
  reported_corroborated: 'Named in reports', reported_tor: 'Tor (in reports)', malware: 'Known malware', kev: 'Exploited vulnerability',
  ids: 'Intrusion alert', historical: 'Outside listing', retro: 'Before listing', sensor: 'Sensor silent', other: 'Threat list',
  own: 'Your list', newdev: 'New device',
};
const PORTS = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'mail', 53: 'DNS', 80: 'web', 443: 'secure web', 445: 'Windows file sharing',
  554: 'camera streaming', 1883: 'MQTT', 3389: 'Remote Desktop', 5900: 'VNC', 8080: 'web', 8443: 'secure web' };
const ACCEPTED = new Set(['SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR', 'established', 'closed']);

// The kind of an alert or incident (same rule as osinthub/netlog/incidents.py KIND_SQL).
export function kindOf(a) {
  const e = a.evidence || {};
  if (isOwn(a.source)) rememberList(a.source, e.indicator?.meta?.list_name);
  for (const x of e.also_listed || []) if (isOwn(x.source)) rememberList(x.source, String(x.source_name || '').replace(/^your list '(.*)'$/, '$1'));
  let k = a.kind;
  if (!k) {
    const cat = e.indicator?.category;
    k = a.rule === 'sensor_silent' ? 'sensor' : a.rule === 'new_device' ? 'newdev' : a.rule === 'ids_signature' ? 'ids'
      : ['historical', 'retro'].includes(a.direction) ? a.direction : cat === 'kev' ? 'kev'
        : `${cat || 'other'}:${['outbound', 'dns'].includes(a.direction) ? 'out' : a.direction === 'inbound' ? 'in' : 'other'}`;
  }
  const [cat, fam0] = k.includes(':') ? k.split(':') : [e.indicator?.category || k, k];
  const fam = fam0 === 'out' ? 'out' : fam0 === 'in' ? 'in' : fam0 === 'other' ? 'unknown' : fam0;
  const rule = a.rule || '';
  const samples = e.sample || [];
  const accepted = /_inbound_accepted/.test(rule) || (fam === 'in' && samples.some((r) => ACCEPTED.has(r.conn_state) && (r.resp_bytes || 0) + (r.orig_bytes || 0) > 0));
  return { key: k, cat, fam, dns: a.direction === 'dns' || (e.rule?.directions || []).includes('dns') && !(e.rule?.directions || []).includes('outbound'),
    accepted, kindLabel: KIND_LABEL[fam === 'out' || fam === 'in' || fam === 'unknown' ? cat : fam] || KIND_LABEL.other };
}

// Device names: the user's label when the devices lane provides one, else the best name we have.
// Read-time names from the API (device_name, evidence.device.name: the user's label) win over anything baked in.
export function dname(id, a) {
  if (!id) return '';
  if (a && a.device === id && (a.device_name || a.evidence?.device?.name)) return a.device_name || a.evidence.device.name;
  const d = S.devices.get(id);
  // d.name already carries the user's label (devices.present); label itself is an object
  return d?.name || (typeof d?.label === 'string' ? d.label : d?.label?.name) || devName(id);
}
// A device with no name of its own, as a headline says it: "an unnamed device (Apple device)", never a raw address.
// Null when the device has a real name (the user's label or a readable one from the logs).
const WEAK_HINT = /^(private address|IPv6 address)$/i;
export function unnamedPhrase(id, a) {
  const mine = a && a.device === id;
  const dv = (mine && a.evidence?.device) || {};
  const d = S.devices.get(id);
  const src = (mine && (a.device_name_source || dv.name_source)) || d?.name_source;
  const raw = !src && /^[0-9a-f:.]+$/i.test(dname(id, a));   // nothing known but the address itself
  if (src !== 'fallback' && !raw) return null;
  let hint = (mine && (a.device_hint ?? dv.hint)) || d?.naming?.hint || '';
  if (WEAK_HINT.test(hint)) hint = '';
  return `an unnamed device${hint ? ` (${hint})` : ''}`;
}
// Every home device in the evidence (an inbound alert can cover several), as names; {phrase: true} for headlines.
export function homeNames(a, { phrase = false } = {}) {
  const e = a.evidence || {}, dv = e.device || {};
  const ids = [...new Set([...(dv.devices || []), ...(a.device ? [a.device] : [])])];
  const names = ids.map((id) => (phrase && unnamedPhrase(id, a)) || dname(id, a));
  const known = new Set(ids.flatMap((id) => S.devices.get(id)?.ips || []));
  for (const ip of dv.home_ips || []) if (!known.has(ip) && !ids.length) names.push(ip);
  return [...new Set(names)];
}
const list = (xs, n = 3) => (xs.length <= n ? xs.join(xs.length === 2 ? ' and ' : ', ').replace(/, ([^,]*)$/, xs.length > 2 ? ', and $1' : ', $1')
  : `${xs.slice(0, n).join(', ')} and ${xs.length - n} more`);
const portOf = (a) => { const s = (a.evidence?.sample || [])[0]; return s?.resp_p ?? null; };
const portName = (p) => (p == null ? '' : `port ${p}${PORTS[p] ? `, ${PORTS[p]}` : ''}`);
// A signature as a person reads it: the demo's made-up rules carry a "DEMO Night Desk" prefix in their raw name; the
// DEMO tag on the alert already says so, so titles drop it (the raw name stays in the evidence and tooltips).
export const sigLabel = (name) => String(name || '').replace(/^DEMO\s+Night\s+Desk\s+/i, '').replace(/^\w/, (c) => c.toUpperCase());
// The matcher stores "(no signature)" when Suricata gave the rule no name: that is no name, never shown as one.
export const NO_SIG = '(no signature)';
export const sigName = (a) => { const n = (a.evidence?.indicator?.observed || [])[0]; return !n || n === NO_SIG ? '' : sigLabel(n); };
// The signature in a sentence: its name in quotes, or "this intrusion signature" when it has none (its sid stays in
// tooltips and Technical details).
export const sigQuoted = (a) => (sigName(a) ? `“${sigName(a)}”` : 'this intrusion signature');
const malware = (a) => a.evidence?.indicator?.meta?.malware;

// Lead (who) and what: the row shows <b>lead</b> what; the detail's headline is both.
export function headline(a) {
  const k = kindOf(a);
  const e = a.evidence || {}, ind = a.indicator || '';
  const homes = homeNames(a, { phrase: true });
  const who = homes.length ? cap(list(homes)) : 'A home device';
  const mw = malware(a) ? ` (${malware(a)})` : '';
  const kindInd = e.indicator?.kind;
  let lead = who, what;
  if (k.fam === 'sensor') { lead = a.indicator || 'A log sender'; what = a.evidence?.state === 'resolved' ? 'was silent, then started sending logs again' : 'stopped sending logs'; }
  else if (k.fam === 'newdev') { lead = 'New device joined:'; what = newName(a); }
  else if (k.fam === 'ids') what = sigName(a) ? `set off an intrusion alert: “${sigName(a)}”` : 'set off an intrusion alert: this intrusion signature has no name';
  else if (k.fam === 'kev') what = `appears to run software with ${ind}, a flaw attackers are exploiting`;
  else if (k.fam === 'historical') what = `contacted ${ind} at a time it was not on ${srcName(a.source)}`;
  else if (k.fam === 'retro') what = `contacted ${ind}${mw} before it was listed, while ${srcName(a.source)} says it was already active`;
  else if (k.fam === 'in') {
    lead = k.cat === 'drop' ? 'An address in a network run by criminals' : k.cat === 'own' ? `An address on ${srcName(a.source)}`
      : `${WHAT[k.cat] ? cap(WHAT[k.cat]) : 'A listed address'}`;
    const p = portName(portOf(a));
    what = k.accepted ? `got in: ${list(homes) || 'a home device'} accepted its connection${p ? ` (${p})` : ''}`
      : `knocked on ${list(homes) || 'a home device'}${p ? ` (${p})` : ''}, and nothing let it in`;
  } else if (k.fam === 'unknown') { lead = 'Two outside addresses'; what = `exchanged traffic involving ${ind}, which ${srcName(a.source)} lists`; }
  else if (k.cat === 'tor' || k.cat === 'reported_tor') what = k.dns ? 'looked up a Tor relay' : 'is using Tor';
  else if (kindInd === 'hash') what = `used a certificate or file that belongs to ${WHAT[k.cat] || 'known malware'}${mw}`;
  else if (kindInd === 'url') what = `fetched a known malware link${mw}`;
  else if (k.cat === 'own') what = `${k.dns ? 'looked up' : 'contacted'} ${rowValue(a) || ind}, which is on ${srcName(a.source)}`;
  else if (k.cat === 'c2') what = k.dns ? `looked up a known botnet controller${mw}` : `is calling a known botnet controller${mw}`;
  else if (k.cat?.startsWith('reported')) what = k.dns || kindInd === 'domain' ? 'looked up a domain named in threat reports' : 'contacted an address named in threat reports';
  else what = `${k.dns ? 'looked up' : 'contacted'} ${WHAT[k.cat] || 'an address on a threat list'}${mw}`;
  return { lead, what, text: `${lead} ${what}` };
}
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
// A new device's name: the user's label when there is one, else what the evidence supports, with the vendor if known.
function newName(a) {
  const dv = a.evidence?.device || {};
  const n = a.device_name || dv.name || dname(a.device, a) || 'a device';
  return dv.vendor && !n.includes(dv.vendor) ? `${n} (${dv.vendor})` : n;
}

// One plain line on why it has this severity (and why it was lowered, when it was).
export function whySeverity(a) {
  const k = kindOf(a), e = a.evidence || {}, sev = a.severity, rule = a.rule || '';
  const tier = e.source_tier || 'C';
  const lists = `${srcName(a.source)} (${TIER_WORDS[tier] || 'a threat list'})`;
  const S0 = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }[sev] || sev;
  const sk = e.sinkhole;
  if (sk?.lowered_from) return `${S0}, lowered from ${sk.lowered_from}: ${sinkName(sk)} blocked every lookup, so the device never got the address.`;
  if (e.capped) return `${S0}, lowered from ${e.original_severity}: at that time the device was trading with many peers (file sharing or a game), where listed home addresses are common.`;
  if (/_spanning$/.test(rule)) return `${S0}, lowered one step: the connection began before the address was listed.`;
  if (/_ambiguous$/.test(rule)) return `${S0}, lowered: it is unclear which side started the connection (it may be a reply to outside traffic).`;
  switch (k.fam) {
    case 'newdev': return 'Info: a new device is not a threat by itself, so it never counts as needing you. Worth a look if you do not recognise it.';
    case 'sensor': return `${S0}: while a sensor is silent, nothing it sees reaches Night Desk, so threats on that part of the network go unseen. It is a blind spot, not proof of an attack.`;
    case 'ids': return `${S0}: this is Suricata's own rating for the signature (you can change it per signature).`;
    case 'kev': return `${S0}: this comes from a software notice in your logs, not from traffic to an attacker. It matters because the flaw is exploited in the wild.`;
    case 'historical': return 'Info: the contact happened while the address was not listed, so it is not evidence of a threat at the time.';
    case 'retro': return 'Low: the contact came before our copy of the list named it; the provider says it was already active, but those are its dates, not our observation.';
    case 'in': return k.accepted
      ? `${S0}: it came from outside, your device accepted it and data moved. Listed by ${lists}.`
      : `${S0}: it came from outside and nothing let it in. The internet is full of these probes.`;
    case 'unknown': return `${S0}: neither side is one of your devices.`;
    default: break;
  }
  if (k.cat === 'own') return `${S0}: your device started it${k.dns ? ' (it looked the name up)' : ''}, and the address is on ${srcName(a.source)}. Night Desk takes your word that it is bad, so your lists alert at medium; it cannot tell how bad.`;
  if (k.cat === 'tor') return `${S0}: Tor is legal and often used on purpose; worth knowing if you did not expect it.`;
  if (k.cat?.startsWith('reported')) {
    const n = e.indicator?.meta?.independent_sources;
    return `${S0}: named by ${n ? `${n} independent publisher${n === 1 ? '' : 's'}` : 'news reports'}${k.cat === 'reported_corroborated' && !(n >= 2) ? ' and also on a threat list' : ''}. Reports alone never make an alert high.`;
  }
  return `${S0}: your device started it${k.dns ? ' (it looked the name up)' : ''}, and the address was on ${lists} at the time${e.interval?.end ? '' : ' and still is'}.`;
}

export const sinkName = (sk) => (sk?.sources || []).map((x) => ({ pihole: 'your Pi-hole', adguard: 'your AdGuard Home' }[x] || x)).join(' and ') || 'your DNS filter';
// One plain line on what the DNS sinkhole did with these lookups, or ''.
export function sinkLine(a) {
  const sk = a.evidence?.sinkhole; if (!sk) return '';
  const who = sinkName(sk).replace(/^your/, 'Your');
  if (sk.all_blocked) return `${who} blocked ${sk.rows === 1 ? 'this lookup' : `all ${sk.rows} lookups`}${sk.reasons?.length ? ` (${sk.reasons.join(', ')})` : ''}.`;
  if (!sk.blocked) return `${who} allowed ${sk.rows === 1 ? 'this lookup' : `these ${sk.rows} lookups`}: the device got the address.`;
  return `${who} blocked ${sk.blocked} of ${sk.rows} lookups and allowed ${sk.allowed}: some got through.`;
}

// Concrete steps for each kind. Returns [{t: html, copy?: text}].
export function whatToDo(a) {
  const k = kindOf(a), e = a.evidence || {}, ind = esc(a.indicator || ''), d = esc(homeNames(a)[0] || 'the device');
  const block = { t: `Block <b class="mono">${ind}</b> on your router or firewall (a block or “alias” rule for ${k.fam === 'in' ? 'traffic coming in' : 'outbound traffic'}).`, copy: a.indicator };
  const expected = 'If you know what this is and it is fine, use <b>This is expected</b> so it stops alerting.';
  const sk = e.sinkhole;
  if (sk?.all_blocked && k.fam === 'out') return [
    { t: `${sinkName(sk).replace(/^your/, 'Your')} already blocked it: ${d} never got the address. Keep that block list on.` },
    { t: `Something on ${d} keeps asking for it. Find the app (Questions: what else it talked to around then); on a computer, run a malware scan.` },
    { others: true },
    { t: expected },
  ];
  switch (k.fam) {
    case 'newdev': {
      const dv = e.device || {};
      return [
        { t: `If you recognise it (a new phone, a guest, a gadget you just set up), acknowledge it, and give it a name and type in Devices so its alerts read well.` },
        { t: `If you do not: find ${dv.mac ? `the MAC <b class="mono">${esc(dv.mac)}</b>` : 'its address'} in your router's list of connected devices. Block it there if it is not yours, and change your Wi-Fi password.` },
        ...(dv.private_mac ? [{ t: 'Its MAC is a private (randomised) one, as phones and laptops use per network: it may be a device you know that changed its address. If so, merge it into that device in Devices.' }] : []),
        { t: 'Put devices you do not fully trust (guests, smart-home gadgets) on a guest network.' },
      ];
    }
    case 'sensor': return a.evidence?.state === 'resolved' ? [
      { t: 'Check that the logs from the silent stretch arrived: Connect logs › Imported files should show files covering it. The sensor sends missed logs on its next run.' },
      { t: 'If it keeps going quiet, check the device\'s power, network and free disk space.' },
    ] : [
      { t: `Check that ${esc(a.indicator || 'the sensor')} is switched on and on the network.` },
      { t: 'Check that it can still reach this machine on the upload port (a firewall or router change can block it).' },
      { t: 'In Import › Device uploads, check that its upload key is still active (not paused, replaced or removed).' },
      { t: 'Check that Zeek or Suricata is still running on it and its disk is not full. The commands to check are below.' },
    ];
    case 'ids': return [
      { t: sigName(a) ? `Read the signature: “${esc(sigName(a))}”. The Questions tab shows which outside address ${d} was talking to.`
        : `This intrusion signature has no name: look its number up in your Suricata rules (it is under Technical details). The Questions tab shows which outside address ${d} was talking to.` },
      { t: `If that address is unknown to you, block it on your router and update ${d}'s firmware.` },
      { t: 'If the signature fires on normal traffic (a false positive), mark it as expected for this device and this kind.' },
    ];
    case 'kev': return [
      { t: `Update or patch the software on ${d}. Check the vendor's advisory for ${ind}.`, link: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(a.indicator || '')}` },
      { t: `If you cannot patch soon, keep ${d} off the internet: no port forwards, no UPnP.` },
      { t: 'Come back after updating: the alert stops when the notice stops appearing in your logs.' },
    ];
    case 'historical': return [{ t: 'Nothing to do now. This is for context: the address was not listed when your device contacted it.' }];
    case 'retro': return [
      { t: `Check whether ${d} still contacts it (Questions: has it contacted it before, and since?).` },
      { t: 'If the contacts continue today, treat it like a botnet alert: take the device offline and update or reset it.' },
      { t: expected },
    ];
    case 'in': {
      const p = portOf(a);
      return k.accepted ? [
        { t: `Check your router's port forwarding and UPnP for ${p != null ? `<b>port ${esc(p)}</b>` : 'this port'} to ${d}. Close it if you do not need it.` },
        { t: `Reach ${d} from outside only through a VPN, not an open port.` },
        { t: `Look at ${d}'s login history for logins from <b class="mono">${ind}</b>; change its passwords and turn on key-only or two-factor login.` },
        block,
        { t: `Update ${d}'s software.` },
      ] : [
        { t: 'Nothing got in. Probes like this hit every internet address many times a day.' },
        { t: `Only if you did not expect ${p != null ? `port ${esc(p)}` : 'that port'} to be reachable: check your router's port forwarding and UPnP.` },
        { t: expected },
      ];
    }
    case 'unknown': return [{ t: 'Check your home prefixes in Network settings: one side may be a home address Night Desk does not know.' }];
    default: break;
  }
  if (k.cat === 'c2' || k.cat === 'malware' || e.indicator?.kind === 'hash' || e.indicator?.kind === 'url') return [
    { t: `Take ${d} off the network now: unplug it, turn off its Wi-Fi, or move it to a guest network.` },
    block,
    { t: `Update ${d}'s firmware or software, or reset it to factory settings; change the passwords it stored.` },
    { others: true },
    { t: 'Come back tomorrow. If contacts continue, the device is still infected.' },
  ];
  if (k.cat === 'drop') return [
    block,
    { t: `Find which app on ${d} made the connection; on a computer, run a malware scan.` },
    { others: true },
  ];
  if (k.cat === 'tor' || k.cat === 'reported_tor') return [
    ...(a.incident?.suppressed ? [] : [{ t: `If someone uses Tor Browser or an app with Tor on ${d}, this is expected: mark it so.` }]),
    { t: `If not, find the app that uses it. Tor on a camera, TV or other gadget is a warning sign: update or reset it.` },
  ];
  if (k.cat === 'own') return [
    { t: `Find which app or service on ${d} made the connection (Questions: what else it talked to around then).` },
    { t: `Block <b class="mono">${ind}</b> on your router or firewall if it is not already.`, copy: a.indicator },
    { others: true },
    { t: `If the entry is out of date, edit or replace the list in Network › Connect logs › Your own lists.` },
  ];
  if (k.cat?.startsWith('reported')) return [
    { t: 'Read the report that named it (below) to see what it is part of.' },
    { t: `If the story fits ${d} (the same malware, app or campaign), block the address and check the device.` },
    { t: expected },
  ];
  return [
    { t: `Find which app or service on ${d} made the connection (Questions: what else it talked to around then).` },
    { t: 'Ads, trackers, games and file sharing often hit listed addresses. If you recognise it, mark it as expected.' },
    { t: `If you do not, block <b class="mono">${ind}</b> on your router and keep an eye on ${d}.`, copy: a.indicator },
  ];
}

// The "what happened" sentences, kind-aware, in plain words.
export function whatHappened(a, inc) {
  const k = kindOf(a), e = a.evidence || {}, iv = e.interval || {};
  const homes = homeNames(a), who = `<b>${esc(list(homes) || 'a home device')}</b>`, Who = `<b>${esc(list(homes) || 'A home device')}</b>`;
  const ind = `<b class="mono">${esc(a.indicator || '')}</b>`;
  const n = inc?.count ?? a.count ?? e.rows ?? 0, t0 = inc?.ts || a.ts, t1 = inc?.last_ts || a.last_ts;
  const when = tsx(t0) === tsx(t1) ? `at ${tsx(t0)}` : `from ${tsx(t0)} to ${tsx(t1)}`;
  const obs = (e.indicator?.observed || [])[0];
  const indSeen = obs && obs !== a.indicator && e.indicator?.kind === 'cidr' ? `<b class="mono">${esc(obs)}</b> (in the range ${ind})` : ind;
  const nc = `${fmt(n)} ${n === 1 ? 'contact' : 'contacts'}`;
  const listed = !iv.start ? '' : a.source === 'reported' ? `News reports have named it since ${tsx(iv.start)}`
    : isOwn(a.source) ? `It is on ${esc(srcName(a.source))} (added ${tsx(iv.start)}${iv.end ? `, until ${tsx(iv.end)}` : ''})`
    : `${esc(srcName(a.source))} has listed it since ${tsx(iv.start)}${iv.end ? ` until ${tsx(iv.end)}` : ' and still does'}`;
  switch (k.fam) {
    case 'newdev': {
      const dv = e.device || {};
      const ips = (dv.home_ips || []).slice(0, 3).map((x) => `<b class="mono">${esc(x)}</b>`).join(', ');
      return `<p><b>${esc(newName(a))}</b> first appeared in your logs at ${tsx(e.first_seen || a.ts)}${dv.mac ? `, with the <span data-term="mac">MAC</span> <b class="mono">${esc(dv.mac)}</b>` : ''}${ips ? ` and the address ${ips}` : ''}. <span data-term="new-device">Night Desk had not seen it before</span>.</p>`;
    }
    case 'ids': {
      const rem = remoteOf(a);
      return `<p><span data-term="suricata">Suricata</span>, the intrusion detector on your network, raised ${sigName(a) ? `“${esc(sigName(a))}”` : 'an alert from this intrusion signature, which has no name,'} for ${who} ${when} (${nc}).${rem ? ` The other side was <b class="mono">${esc(rem)}</b>.` : ''}</p>`;
    }
    case 'kev': return `<p>A software notice in your logs says ${who} runs a version affected by ${ind}. <span data-term="kev">CISA lists it as exploited in the wild</span>. Seen ${when}.</p>`;
    case 'in': return `<p>${ind} <span data-term="direction">connected <i>to</i></span> ${who} ${when} (${nc}). ${k.accepted ? 'Your device answered and data moved.' : 'Nothing answered or the connection was refused.'}${listed ? ` ${listed}.` : ''}</p>`;
    case 'historical': return `<p>${Who} contacted ${ind} ${when}, <span data-term="historical">outside the time</span> ${esc(srcName(a.source))} listed it${iv.start ? ` (listed ${tsx(iv.start)}${iv.end ? ` to ${tsx(iv.end)}` : ''})` : ''}.</p>`;
    case 'retro': return `<p>${Who} contacted ${ind} ${when}. Our copy of ${esc(srcName(a.source))} named it only from ${tsx(iv.start)}, but <span data-term="before-listing">the provider says it was active</span> from ${esc(e.indicator?.meta?.first_seen ? T.date(e.indicator.meta.first_seen) : '?')}.</p>`;
    default: return `<p>${Who} ${k.dns ? '<span data-term="dns">looked up a name</span> pointing to' : '<span data-term="direction">connected to</span>'} ${indSeen} ${when} (${nc}). ${listed}.</p>`;
  }
}
// Times in sentences use the app's one clock (core/time.js); the pane's header names the zone.
const tsx = (t) => (t ? T.stamp(t) : '—');

// The outside address in an IDS alert (the signature is not an address).
export function remoteOf(a) {
  const homes = new Set(a.evidence?.device?.home_ips || []);
  for (const r of [...(a.rows || []), ...(a.evidence?.sample || [])]) {
    for (const ip of [r.resp_h, r.orig_h]) if (ip && !homes.has(ip)) return ip;
  }
  return null;
}

// The value a row shows: the outside address for an IDS alert, the address seen inside a listed range, else the indicator.
export function rowValue(a) {
  const k = kindOf(a), e = a.evidence || {};
  if (k.fam === 'ids') return remoteOf(a) || '';
  const obs = (e.indicator?.observed || [])[0];
  return obs && e.indicator?.kind === 'cidr' ? obs : a.indicator || '';
}

// Error copy (B2-11): a server that answered with an error (a 500) is running, so never "did not answer"; a 404 is
// handled by each caller as "no longer exists". `e` is the error api.js throws (e.status set when the server answered).
export const serverWhy = (e) => (e?.status ? 'The Night Desk server is running but answered with an error.' : 'The Night Desk server did not answer.');

// "any intrusion alert", "any botnet controller alert": every kind label as a whole phrase, so none reads doubled or
// broken ("any named in reports alert", "any outside listing alert"). A label not in the table falls back to
// "any <label> alert" with the words lowercased mid-sentence except names and acronyms ("Tor", "DROP").
const ANY_KIND = {
  'Botnet controller': 'any botnet controller alert', 'Criminal network (DROP)': 'any alert about a criminal network (DROP)',
  'Compromised host': 'any compromised-host alert', 'Bad reputation': 'any bad-reputation alert', 'Threat list': 'any threat-list alert',
  'Known attacker': 'any known-attacker alert', 'Internet scanner': 'any internet-scanner alert', Tor: 'any Tor alert',
  'Named in reports': 'any alert about an address named in reports', 'Tor (in reports)': 'any alert about a Tor relay named in reports',
  'Known malware': 'any known-malware alert', 'Exploited vulnerability': 'any exploited-vulnerability alert', 'Intrusion alert': 'any intrusion alert',
  'Outside listing': 'any contact made while the address was not listed', 'Before listing': 'any contact made before the address was listed',
  'Sensor silent': 'any silent-sensor alert', 'Your list': 'any alert from your own lists', 'New device': 'any new-device alert',
};
export const midSentence = (label) => String(label || '').split(' ').map((w) => (/^[A-Z][a-z]/.test(w) && w !== 'Tor' ? w.toLowerCase() : w)).join(' ');
// An incident's span in the alert list: true for one contact ("one contact", never "1 day"), the real length
// within one day ("3 hours"), else its days (or the daily alerts it joins).
export function spanText(a) {
  if (a.days > 1) return `${a.days} days`;
  if (a.n_alerts > 1) return `${a.n_alerts} parts`;
  if ((a.count ?? 1) <= 1) return 'one contact';
  const ms = Date.parse(a.last_ts) - Date.parse(a.ts);
  return ms >= 1000 ? durWords(ms) : 'within a second';
}
// A kind label as the word before "alert(s)": "intrusion" for "Intrusion alert", so no copy says "alert alert".
export const kindWord = (label) => midSentence(label || 'matching').replace(/\s+alerts?$/i, '');
export const anyKind = (label) => { if (ANY_KIND[label]) return ANY_KIND[label]; const l = midSentence(label); return `any ${l}${/\balerts?$/i.test(l) ? '' : ' alert'}`; };
// What a rule's indicator is, in words: "this signature", "this domain", "this address range", "this address".
export function indicatorNoun(a) {
  const kind = a?.evidence?.indicator?.kind;
  return kind === 'signature' ? 'signature' : kind === 'domain' ? 'domain' : kind === 'cidr' ? 'address range' : kind === 'cve' ? 'vulnerability' : 'address';
}
// Rule scope in words ("this device + this address").
export function scopeText(r) {
  const k = r.kind ? (KIND_LABEL[r.kind.split(':')[0]] || KIND_LABEL[r.kind] || r.kind) : null;
  // a signature rule names the signature (its sid only in the tooltip), as the alert does (followups netdetail r1)
  const named = r.indicator_label && r.indicator_label !== NO_SIG;
  const ind = !r.indicator ? null : named ? `<span class="netdetail-sig" title="${esc(r.indicator)}">“${esc(sigLabel(r.indicator_label))}”</span>`
    : /^sid:/.test(r.indicator) ? `<span title="${esc(r.indicator)}">this intrusion signature</span>` : `<span class="mono">${esc(r.indicator)}</span>`;
  const parts = [r.device ? esc(dname(r.device)) : 'any device', ind,
    k ? esc(anyKind(k)) : null].filter(Boolean);
  return parts.join(' + ');
}
