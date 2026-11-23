#!/usr/bin/env python3
"""Round-3 critic for osinthub/netlog: realism.

Home = documentation prefixes (192.0.2.0/24, 2001:db8:1::/48), invented MACs. External addresses are real
public service addresses written from the critic's own knowledge (not the builder's tranco200 fixture),
plus documentation addresses for invented reported IOCs and a C2.

Phases (run against a SCRATCH lake only):
    # server stopped: add articles, mentions and claims (the entities/news tables) for the reported-IOC path
    uv run python tests/eval/critic/netlog_r3.py --lake <lake> --seed
    # server running (OSINTHUB_DISABLE_EXT=entities is fine: the tables are created by --seed)
    uv run python tests/eval/critic/netlog_r3.py --lake <lake> --base http://127.0.0.1:8816 --phase benign
    uv run python tests/eval/critic/netlog_r3.py --lake <lake> --base ... --phase reported
    uv run python tests/eval/critic/netlog_r3.py --lake <lake> --base ... --phase timely
    uv run python tests/eval/critic/netlog_r3.py --lake <lake> --base ... --phase usability
"""
from __future__ import annotations

import argparse, collections, gzip, io, json, random, sys, time, urllib.parse, urllib.request
from datetime import UTC, datetime
from pathlib import Path

HOME = ["192.0.2.0/24", "2001:db8:1::/48"]
DAY = "2026-11-05"
ROUTER, ROUTER_MAC = "192.0.2.1", "00:00:5e:00:53:fe"
C2_LISTED = ("162.243.103.246", 8080)        # on the seed lake's feodo_c2 list since 2026-11-04 18:33
NEW_C2 = "203.0.113.99"                      # listed by a feodo delta written in --phase timely
REP = {  # invented reported IOCs (documentation space) and the expected outcome
    "prose": "198.51.100.50", "single": "198.51.100.51", "two_vendor": "198.51.100.52", "syndicated": "198.51.100.53",
    "expired": "203.0.113.70", "geo_claim": "203.0.113.80", "malware_claim": "203.0.113.81", "five_src": "203.0.113.82",
}

# 15 devices: (name, ip4, mac, kind)
DEVICES = [
    ("iphone-anna", "192.0.2.21", "00:00:5e:00:53:01", "ios"), ("iphone-ben", "192.0.2.22", "00:00:5e:00:53:02", "ios"),
    ("pixel-kid", "192.0.2.23", "00:00:5e:00:53:03", "android"), ("ipad-family", "192.0.2.24", "00:00:5e:00:53:04", "ios"),
    ("macbook-anna", "192.0.2.25", "00:00:5e:00:53:05", "mac"), ("thinkpad-ben", "192.0.2.26", "00:00:5e:00:53:06", "win"),
    ("lg-oled-tv", "192.0.2.27", "00:00:5e:00:53:07", "tv"), ("roku-bedroom", "192.0.2.28", "00:00:5e:00:53:08", "roku"),
    ("synology-nas", "192.0.2.29", "00:00:5e:00:53:09", "nas"), ("xbox-series", "192.0.2.30", "00:00:5e:00:53:0a", "xbox"),
    ("echo-kitchen", "192.0.2.31", "00:00:5e:00:53:0b", "alexa"), ("nest-thermostat", "192.0.2.32", "00:00:5e:00:53:0c", "nest"),
    ("hue-bridge", "192.0.2.33", "00:00:5e:00:53:0d", "hue"), ("ring-doorbell", "192.0.2.34", "00:00:5e:00:53:0e", "ring"),
    ("wyze-cam-garage", "192.0.2.35", "00:00:5e:00:53:0f", "cam"),
]

# Real public services (critic's own knowledge). name -> (addresses, port, proto, typical bytes)
S = {
    "www.google.com": (["142.250.80.36", "142.250.72.100", "2607:f8b0:4006:80e::2004"], 443),
    "www.youtube.com": (["142.250.80.46", "142.250.65.206"], 443),
    "rr4---sn-8xgp1vo-p5qe.googlevideo.com": (["173.194.55.9", "173.194.141.105"], 443),
    "play.googleapis.com": (["142.250.65.170"], 443),
    "android.clients.google.com": (["142.250.80.14"], 443),
    "mtalk.google.com": (["142.250.102.188"], 5228),
    "dns.google": (["8.8.8.8", "8.8.4.4"], 443),
    "mozilla.cloudflare-dns.com": (["104.16.248.249", "104.16.249.249"], 443),
    "gateway.icloud.com": (["17.248.185.41", "17.248.185.36"], 443),
    "courier.push.apple.com": (["17.57.146.20", "17.57.146.22"], 5223),
    "mesu.apple.com": (["17.253.23.205"], 443),
    "updates.cdn-apple.com": (["17.253.17.207"], 443),
    "www.msftconnecttest.com": (["13.107.4.52"], 80),
    "login.microsoftonline.com": (["20.190.151.7", "40.126.31.69"], 443),
    "outlook.office365.com": (["52.96.165.18", "52.98.151.66"], 443),
    "settings-win.data.microsoft.com": (["20.42.73.29"], 443),
    "tlu.dl.delivery.mp.microsoft.com": (["8.248.97.254", "8.241.123.126"], 80),
    "www.bing.com": (["13.107.21.200", "204.79.197.200"], 443),
    "user.auth.xboxlive.com": (["20.199.120.151"], 443),
    "www.netflix.com": (["54.155.178.5", "52.31.97.134"], 443),
    "ipv4-c021-lhr001-ix.1.oca.nflxvideo.net": (["45.57.40.1", "198.38.120.130"], 443),
    "atv-ext.amazon.com": (["13.32.110.24", "99.84.208.70"], 443),
    "avs-alexa-4-na.amazon.com": (["52.94.233.129", "54.239.21.157"], 443),
    "device-metrics-us.amazon.com": (["52.46.149.95"], 443),
    "api.roku.com": (["52.21.115.12", "3.217.200.60"], 443),
    "lgtvonline.lge.com": (["3.33.252.61"], 443),
    "snu.lge.com": (["165.244.120.140"], 443),
    "spclient.wg.spotify.com": (["35.186.224.25"], 443),
    "global.quickconnect.to": (["3.124.150.11"], 443),
    "checkip.synology.com": (["52.28.165.95"], 443),
    "s3.us-west-004.backblazeb2.com": (["149.137.136.20"], 443),
    "plex.tv": (["52.214.89.180", "172.67.68.168"], 443),
    "registry-1.docker.io": (["54.227.20.253"], 443),
    "production.cloudflare.docker.com": (["104.16.101.215"], 443),
    "archive.ubuntu.com": (["91.189.91.82", "185.125.190.36"], 80),
    "frontdoor.nest.com": (["34.117.183.168"], 443),
    "ws.meethue.com": (["52.209.247.102"], 443),
    "es.ring.com": (["52.4.94.12", "3.229.233.33"], 443),
    "api.wyzecam.com": (["54.149.250.115"], 443),
    "discord.com": (["162.159.137.232", "162.159.128.233"], 443),
    "gateway.discord.gg": (["162.159.135.234"], 443),
    "cdn.discordapp.com": (["162.159.129.233"], 443),
    "api.telegram.org": (["149.154.167.220"], 443),
    "client.dropbox.com": (["162.125.1.20"], 443),
    "api.dropboxapi.com": (["162.125.4.19"], 443),
    "g.whatsapp.net": (["157.240.214.60", "2a03:2880:f20c:c4:face:b00c:0:167"], 443),
    "zoom.us": (["170.114.52.2"], 443),
    "github.com": (["140.82.112.3", "140.82.114.4"], 443),
    "incoming.telemetry.mozilla.org": (["34.120.208.123"], 443),
    "www.reddit.com": (["151.101.1.140"], 443),
    "api.steampowered.com": (["23.47.27.74"], 443),
    "cache1-ams1.steamcontent.com": (["155.133.230.34"], 80),
    "video-weaver.ams03.hls.ttvnw.net": (["99.181.79.4"], 443),
    "disney.api.edge.bamgrid.com": (["54.230.111.29"], 443),
    "www.facebook.com": (["157.240.214.35", "2a03:2880:f12f:83:face:b00c:0:25de"], 443),
}
NTP = {"time.apple.com": ["17.253.4.125", "17.253.20.125"], "time.google.com": ["216.239.35.0", "216.239.35.4"],
       "time.cloudflare.com": ["162.159.200.1", "162.159.200.123"], "time.windows.com": ["40.119.6.228"],
       "time.nist.gov": ["129.6.15.28", "132.163.97.1"], "time.aws.com": ["169.254.169.123"]}
PROFILE = {
    "ios": ["www.google.com", "gateway.icloud.com", "courier.push.apple.com", "mesu.apple.com", "www.youtube.com",
            "rr4---sn-8xgp1vo-p5qe.googlevideo.com", "g.whatsapp.net", "www.facebook.com", "spclient.wg.spotify.com",
            "api.telegram.org", "www.netflix.com", "ipv4-c021-lhr001-ix.1.oca.nflxvideo.net", "www.reddit.com"],
    "android": ["www.google.com", "android.clients.google.com", "play.googleapis.com", "mtalk.google.com", "dns.google",
                "www.youtube.com", "rr4---sn-8xgp1vo-p5qe.googlevideo.com", "discord.com", "gateway.discord.gg",
                "cdn.discordapp.com", "video-weaver.ams03.hls.ttvnw.net", "g.whatsapp.net"],
    "mac": ["www.google.com", "gateway.icloud.com", "courier.push.apple.com", "updates.cdn-apple.com", "zoom.us",
            "github.com", "mozilla.cloudflare-dns.com", "incoming.telemetry.mozilla.org", "client.dropbox.com",
            "api.dropboxapi.com", "outlook.office365.com", "www.reddit.com", "spclient.wg.spotify.com"],
    "win": ["www.msftconnecttest.com", "login.microsoftonline.com", "settings-win.data.microsoft.com",
            "tlu.dl.delivery.mp.microsoft.com", "www.bing.com", "api.steampowered.com", "cache1-ams1.steamcontent.com",
            "discord.com", "gateway.discord.gg", "cdn.discordapp.com", "api.telegram.org", "github.com", "www.google.com"],
    "tv": ["lgtvonline.lge.com", "snu.lge.com", "www.netflix.com", "ipv4-c021-lhr001-ix.1.oca.nflxvideo.net",
           "www.youtube.com", "rr4---sn-8xgp1vo-p5qe.googlevideo.com", "disney.api.edge.bamgrid.com", "atv-ext.amazon.com"],
    "roku": ["api.roku.com", "www.netflix.com", "ipv4-c021-lhr001-ix.1.oca.nflxvideo.net", "atv-ext.amazon.com",
             "video-weaver.ams03.hls.ttvnw.net"],
    "nas": ["global.quickconnect.to", "checkip.synology.com", "s3.us-west-004.backblazeb2.com", "plex.tv",
            "registry-1.docker.io", "production.cloudflare.docker.com", "archive.ubuntu.com"],
    "xbox": ["user.auth.xboxlive.com", "tlu.dl.delivery.mp.microsoft.com", "www.netflix.com", "settings-win.data.microsoft.com"],
    "alexa": ["avs-alexa-4-na.amazon.com", "device-metrics-us.amazon.com", "spclient.wg.spotify.com"],
    "nest": ["frontdoor.nest.com"], "hue": ["ws.meethue.com"], "ring": ["es.ring.com"], "cam": ["api.wyzecam.com"],
}
NTP_OF = {"ios": "time.apple.com", "mac": "time.apple.com", "android": "time.google.com", "win": "time.windows.com",
          "tv": "time.google.com", "roku": "time.cloudflare.com", "nas": "time.nist.gov", "xbox": "time.windows.com",
          "alexa": "time.google.com", "nest": "time.google.com", "hue": "time.cloudflare.com", "ring": "time.nist.gov",
          "cam": "time.google.com"}
BIG = {"rr4---sn-8xgp1vo-p5qe.googlevideo.com", "ipv4-c021-lhr001-ix.1.oca.nflxvideo.net", "atv-ext.amazon.com",
       "cache1-ams1.steamcontent.com", "s3.us-west-004.backblazeb2.com", "video-weaver.ams03.hls.ttvnw.net",
       "tlu.dl.delivery.mp.microsoft.com", "es.ring.com"}

RANK = {None: -1, "info": 0, "low": 1, "medium": 2, "high": 3}


def T(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def req(base, method, path, body=None, files=None, timeout=900):
    data, hdr = None, {}
    if files is not None:
        b = "----critic3" + str(time.time_ns())
        buf = io.BytesIO()
        for name, content in files:
            buf.write(f"--{b}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\n"
                      "Content-Type: application/octet-stream\r\n\r\n".encode())
            buf.write(content); buf.write(b"\r\n")
        buf.write(f"--{b}--\r\n".encode())
        data, hdr = buf.getvalue(), {"Content-Type": f"multipart/form-data; boundary={b}"}
    elif body is not None:
        data, hdr = json.dumps(body).encode(), {"Content-Type": "application/json"}
    r = urllib.request.Request(base + path, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, "body": e.read().decode(errors="replace")[:300]}


def g(base, path, **p):
    return req(base, "GET", path + ("?" + urllib.parse.urlencode(p) if p else ""))


class Gen:
    def __init__(self, seed=3):
        self.rnd, self.n, self.rows = random.Random(seed), 0, []

    def uid(self):
        self.n += 1
        return f"Cr3{self.n:09d}"

    def dns(self, ts, client, name, answers, server=ROUTER, qtype="A"):
        self.rows.append({"_path": "dns", "ts": ts, "uid": self.uid(), "id.orig_h": client, "id.orig_p": self.rnd.randint(30000, 60000),
                          "id.resp_h": server, "id.resp_p": 53, "proto": "udp", "trans_id": self.rnd.randint(1, 65535),
                          "query": name, "qtype": 1 if qtype == "A" else 28, "qtype_name": qtype, "rcode_name": "NOERROR",
                          "answers": answers, "TTLs": [300.0] * len(answers)})

    def conn(self, ts, o, r, rp, proto="tcp", service="ssl", ob=2000, rb=8000, dur=3.0, state="SF", op=None, sni=None,
             mac=None, rmac=None):
        u = self.uid()
        row = {"_path": "conn", "ts": ts, "uid": u, "id.orig_h": o, "id.orig_p": op or self.rnd.randint(49152, 65535),
               "id.resp_h": r, "id.resp_p": rp, "proto": proto, "service": service, "duration": dur, "orig_bytes": ob,
               "resp_bytes": rb, "conn_state": state, "history": "ShADadFf" if proto == "tcp" else "Dd",
               "orig_pkts": max(1, ob // 1200), "resp_pkts": max(1, rb // 1200)}
        if mac:
            row["orig_l2_addr"] = mac
        if rmac:
            row["resp_l2_addr"] = rmac
        self.rows.append(row)
        if sni:
            self.rows.append({"_path": "ssl", "ts": ts + 0.05, "uid": u, "id.orig_h": o, "id.orig_p": row["id.orig_p"],
                              "id.resp_h": r, "id.resp_p": rp, "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
                              "server_name": sni, "established": True})
        return u


def benign_day(day=DAY, seed=3) -> list[dict]:
    G = Gen(seed)
    rnd = G.rnd
    base = T(f"{day}T00:00:00Z")
    for name, ip, mac, kind in DEVICES:
        G.rows.append({"_path": "dhcp", "ts": base + rnd.random() * 120, "uids": [G.uid()], "client_addr": ip,
                       "server_addr": ROUTER, "mac": mac, "host_name": name, "assigned_addr": ip, "lease_time": 86400.0,
                       "msg_types": ["REQUEST", "ACK"]})
    for name, ip, mac, kind in DEVICES:
        prof = PROFILE[kind]
        n_sessions = {"nest": 60, "hue": 60, "ring": 120, "cam": 150}.get(kind, 220)
        v6 = f"2001:db8:1:0:{rnd.randint(0x1000, 0xffff):x}:{rnd.randint(0x1000, 0xffff):x}:{rnd.randint(0x1000, 0xffff):x}:{rnd.randint(0x1000, 0xffff):x}"
        for _ in range(n_sessions):
            t = base + rnd.random() * 82000
            svc = rnd.choice(prof)
            addrs, port = S[svc]
            dst = rnd.choice(addrs)
            src = v6 if ":" in dst else ip
            if svc in ("dns.google", "mozilla.cloudflare-dns.com"):     # DoH: no plain DNS lookup
                G.conn(t, src, dst, 443, sni=svc, ob=30000, rb=60000, dur=600, mac=mac)
                continue
            G.dns(t, ip, svc, [a for a in addrs if (":" in a) == (":" in dst)] or addrs, qtype="AAAA" if ":" in dst else "A")
            big = svc in BIG
            ob = rnd.randint(800, 20000) if not (big and kind == "nas") else rnd.randint(50_000_000, 400_000_000)
            rb = rnd.randint(50_000_000, 900_000_000) if big and kind != "nas" else rnd.randint(2000, 200000)
            svcname = "http" if port == 80 else None if port in (5223, 5228) else "ssl"
            G.conn(t + 0.02, src, dst, port, service=svcname, ob=ob, rb=rb, dur=rnd.uniform(1, 3600 if big else 120),
                   sni=svc if port == 443 else None, mac=mac)
        # NTP every ~hour
        nsrv = NTP_OF[kind]
        for h in range(0, 23):
            t = base + h * 3600 + rnd.random() * 600
            dst = rnd.choice(NTP[nsrv])
            G.dns(t, ip, nsrv, NTP[nsrv])
            G.conn(t + 0.01, ip, dst, 123, proto="udp", service="ntp", ob=48, rb=48, dur=0.03, op=123, mac=mac)
        # mDNS, SSDP, LLMNR, NetBIOS broadcasts
        for _ in range(30):
            t = base + rnd.random() * 82000
            G.conn(t, ip, "224.0.0.251", 5353, proto="udp", service="dns", ob=300, rb=0, state="S0", op=5353, mac=mac)
            G.conn(t + 1, v6, "ff02::fb", 5353, proto="udp", service="dns", ob=300, rb=0, state="S0", op=5353)
            G.conn(t + 2, ip, "239.255.255.250", 1900, proto="udp", service=None, ob=180, rb=0, state="S0", mac=mac)
        if kind in ("win", "mac"):
            for _ in range(10):
                t = base + rnd.random() * 82000
                G.conn(t, ip, "192.0.2.255", 137, proto="udp", service="dns", ob=50, rb=0, state="S0", op=137, mac=mac)
                G.conn(t, ip, "224.0.0.252", 5355, proto="udp", service="dns", ob=60, rb=0, state="S0", mac=mac)
        # local: phones cast to the TV, NAS SMB from laptops
        if kind in ("ios", "android"):
            for _ in range(10):
                G.conn(base + rnd.random() * 82000, ip, "192.0.2.27", 8009, ob=4000, rb=4000, mac=mac, service="ssl")
        if kind in ("mac", "win"):
            for _ in range(20):
                G.conn(base + rnd.random() * 82000, ip, "192.0.2.29", 445, service="smb", ob=5_000_000, rb=50_000_000, mac=mac)
    # router's own upstream DNS (DoT to Quad9) and DHCP from router
    for _ in range(200):
        G.conn(base + rnd.random() * 82000, ROUTER, rnd.choice(["9.9.9.9", "149.112.112.112"]), 853, service="ssl",
               ob=4000, rb=9000, dur=300, mac=ROUTER_MAC)
    # Plex remote access: NAS port 32400 forwarded; friends stream in, scanners poke it
    for _ in range(6):
        t = base + rnd.random() * 80000
        G.conn(t, rnd.choice(["82.132.214.18", "86.4.112.71", "2.98.201.33"]), "192.0.2.29", 32400, ob=40000,
               rb=1_500_000_000, dur=5400, service="ssl")
    return G.rows


def list_ips(lake: Path, source: str) -> list[str]:
    out = []
    for f in sorted((lake / "raw" / source).glob("*/*/*/*.records.ndjson.gz"))[:1]:
        for line in gzip.open(f, "rt"):
            r = json.loads(line)
            if r["op"] == "put":
                out.append(r["key"].split(":")[0] if source == "feodo_c2" else r["key"])
    return out


def noise_rows(lake: Path, day=DAY, seed=5) -> list[dict]:
    """Internet background noise against the forwarded Plex port, from addresses on the lake's own lists."""
    G = Gen(seed)
    G.n = 500000
    rnd = G.rnd
    base = T(f"{day}T00:00:00Z")
    picks = {s: rnd.sample(list_ips(lake, s), 4) for s in ("dshield_top", "blocklist_de", "et_compromised", "tor_exits")}
    for s, ips in picks.items():
        for ip in ips:
            for _ in range(3):
                G.conn(base + rnd.random() * 80000, ip, "192.0.2.29", 32400, state=rnd.choice(["S0", "REJ"]), ob=0, rb=0, dur=0)
            # one banner grab: TLS handshake + Plex web page (~15 kB)
            G.conn(base + rnd.random() * 80000, ip, "192.0.2.29", 32400, state="SF", ob=600, rb=15000, dur=1.5)
    return G.rows, picks


def p2p_rows(lake: Path, day=DAY, seed=9) -> list[dict]:
    """A laptop seeding a Linux ISO: a swarm whose residential peers partly sit on the blocklists."""
    G = Gen(seed)
    G.n = 700000
    rnd = G.rnd
    base = T(f"{day}T18:00:00Z")
    listed = rnd.sample(list_ips(lake, "blocklist_de"), 6) + rnd.sample(list_ips(lake, "et_compromised"), 2)
    peers = listed + [f"{rnd.randint(60, 220)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(60)]
    for p in peers:
        G.conn(base + rnd.random() * 10000, "192.0.2.26", p, rnd.choice([6881, 51413, 6889]), service=None,
               ob=rnd.randint(2_000_000, 40_000_000), rb=rnd.randint(50_000, 900_000), dur=rnd.uniform(60, 2000))
        if rnd.random() < 0.5:
            G.conn(base + rnd.random() * 10000, p, "192.0.2.26", 51413, service=None, ob=200_000, rb=rnd.randint(1_000_000, 30_000_000),
                   dur=rnd.uniform(60, 2000))
    return G.rows, listed


def problem_rows(day=DAY) -> list[dict]:
    """The real problem: the garage camera beacons to a listed Feodo C2, and the laptop hits reported IOCs."""
    G = Gen(11)
    G.n = 900000
    base = T(f"{day}T00:00:00Z")
    cam = "192.0.2.35"
    for h in range(2, 22):
        G.conn(base + h * 3600 + 17, cam, C2_LISTED[0], C2_LISTED[1], service="http", ob=900, rb=1400, dur=1.1,
               mac="00:00:5e:00:53:0f")
    return G.rows


def reported_traffic(day=DAY) -> list[dict]:
    G = Gen(13)
    G.n = 950000
    base = T(f"{day}T00:00:00Z")
    win = "192.0.2.26"
    for i, key in enumerate(["prose", "single", "two_vendor", "syndicated", "expired", "geo_claim", "malware_claim", "five_src"]):
        G.conn(base + 36000 + i * 60, win, REP[key], 443, ob=3000, rb=5000, sni=None)
    # five_src also connects inbound, accepted, with lots of data
    G.conn(base + 40000, REP["five_src"], win, 3389, service="rdp", ob=3_000_000, rb=8_000_000, dur=1800)
    # expired IP: contacted inside its old window too
    G.conn(T("2026-09-10T12:00:00Z"), "192.0.2.29", REP["expired"], 443, ob=3000, rb=5000)
    # reported domains
    G.dns(base + 39000, win, "evil-update.example", ["198.51.100.60"])
    G.conn(base + 39000.1, win, "198.51.100.60", 443, sni="evil-update.example")
    G.dns(base + 39100, win, "ancient-c2.example", ["198.51.100.61"])
    return G.rows


def ndjson(rows) -> bytes:
    return gzip.compress("".join(json.dumps(r) + "\n" for r in rows).encode())


# ---------------------------------------------------------------- seeding (server stopped)

ART = {
    "art-a": ("Vendor Alpha Labs", "2026-11-04T12:00:00Z", "story-loaderx", """LoaderX returns with new infrastructure

Vendor Alpha Labs analysed a LoaderX campaign. Before contacting its server, the sample checks connectivity with
discord.com and api.telegram.org and fetches its public address from ipinfo.io. An unrelated scanner, 198.51.100.50,
also appeared in our honeypot logs during the period.

Indicators of Compromise

Network indicators:
198.51.100[.]51
198[.]51[.]100[.]52
198[.]51[.]100[.]53
203[.]0[.]113[.]82
evil-update[.]example
discord[.]com
cdn.discordapp[.]com
api.telegram[.]org
api.dropboxapi[.]com
ipinfo[.]io
www.bing[.]com
8[.]8[.]8[.]8
104[.]16[.]101[.]215
{tor}
"""),
    "art-d": ("Vendor Delta Research", "2026-11-04T15:00:00Z", "story-other", """Same loader, different operator

Our telemetry agrees with other vendors.

IOCs
198[.]51[.]100[.]52
203[.]0[.]113[.]82
discord[.]com
api.telegram[.]org
"""),
    "art-e": ("Daily Security Newswire", "2026-11-04T16:00:00Z", "story-loaderx", """LoaderX is back, researchers say

Vendor Alpha Labs published the following indicators, which we reproduce here:

198[.]51[.]100[.]53
"""),
    "art-c": ("Vendor Gamma", "2026-08-01T09:00:00Z", "story-old", """Old campaign

Indicators of compromise
203[.]0[.]113[.]70
"""),
    "art-f": ("Vendor Zeta", "2026-02-01T09:00:00Z", "story-ancient", """Ancient campaign

Indicators of compromise
ancient-c2[.]example
"""),
}
MENTIONS = [  # (entity type, value, article)
    ("ip", "198.51.100.50", "art-a"), ("ip", "198.51.100.51", "art-a"), ("ip", "198.51.100.52", "art-a"),
    ("ip", "198.51.100.53", "art-a"), ("ip", "203.0.113.82", "art-a"), ("domain", "evil-update.example", "art-a"),
    ("domain", "discord.com", "art-a"), ("domain", "cdn.discordapp.com", "art-a"), ("domain", "api.telegram.org", "art-a"),
    ("domain", "api.dropboxapi.com", "art-a"), ("domain", "ipinfo.io", "art-a"), ("domain", "www.bing.com", "art-a"),
    ("ip", "8.8.8.8", "art-a"), ("ip", "104.16.101.215", "art-a"),
    ("ip", "198.51.100.52", "art-d"), ("ip", "203.0.113.82", "art-d"), ("domain", "discord.com", "art-d"),
    ("domain", "api.telegram.org", "art-d"),
    ("ip", "198.51.100.53", "art-e"), ("ip", "203.0.113.70", "art-c"), ("domain", "ancient-c2.example", "art-f"),
]
CLAIMS = [  # (subj, predicate, obj, sources, ts)
    ("ip:203.0.113.80", "located_in", "country:nl", ["Vendor Beta"], "2026-11-04T10:00:00Z"),
    ("malware:loaderx", "communicates_with", "ip:203.0.113.81", ["Vendor Alpha Labs"], "2026-11-04T10:00:00Z"),
    ("actor:ta-loader", "uses", "ip:203.0.113.82", ["Vendor Beta", "Vendor Epsilon", "Vendor Eta"], "2026-11-04T10:00:00Z"),
]


def seed(lake: Path):
    import duckdb
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from osinthub.entities.store import SCHEMA as ESCHEMA
    from osinthub.news.schema import SCHEMA as NSCHEMA
    tor = list_ips(lake, "tor_exits")[7]
    c = duckdb.connect(str(lake / "db" / "hub.duckdb"))
    c.execute(ESCHEMA)
    c.execute(NSCHEMA)
    for aid, (src, ts, story, text) in ART.items():
        text = text.replace("{tor}", tor.replace(".", "[.]"))
        c.execute("INSERT OR REPLACE INTO articles (id, url, source, title, published, fetched_at, text, story_id, status) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ok')",
                  [aid, f"https://{src.split()[0].lower()}.example/{aid}", src, text.splitlines()[0], ts, ts, text, story])
    ments = MENTIONS + [("ip", tor, "art-a")]
    for kind, v, aid in ments:
        eid = f"{kind}:{v}"
        ts = ART[aid][1]
        c.execute("INSERT OR IGNORE INTO entities (id, type, name, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)", [eid, kind, v, ts, ts])
        c.execute("INSERT OR IGNORE INTO mentions VALUES (?, 'article', ?, 'mentioned', 'regex', 0.9, ?)", [eid, aid, ts])
    for i, (s, p, o, srcs, ts) in enumerate(CLAIMS):
        for eid in (s, o):
            k, v = eid.split(":", 1)
            c.execute("DELETE FROM entities WHERE id = ?", [eid])
            c.execute("INSERT INTO entities (id, type, name, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)", [eid, k, v, ts, ts])
        c.execute("DELETE FROM claims WHERE id = ?", [f"critic3-{i}"])
        c.execute("INSERT INTO claims VALUES (?, ?, ?, ?, 'reported', ?, 0.8, ?, ?, '[]')", [f"critic3-{i}", s, p, o, srcs, ts, ts])
    c.close()
    print(json.dumps({"seeded": True, "tor_exit_reported": tor}))


# ---------------------------------------------------------------- phases

def all_alerts(base):
    return g(base, "/api/netlog/alerts", limit=0)


def tally(alerts, title):
    by = collections.Counter(a["severity"] for a in alerts)
    print(f"== {title}: {len(alerts)} alerts {dict(by)}")
    for a in sorted(alerts, key=lambda a: -RANK[a["severity"]]):
        if a["severity"] in ("high", "medium", "low"):
            print(f"   {a['severity']:6} {a['rule']:32} {a['indicator']:22} {a['source']:15} dev={a['device']} n={a['count']}")
    return by


def phase_benign(base, lake):
    print(req(base, "PUT", "/api/netlog/settings", {"home_prefixes": HOME}).get("home_prefixes"))
    day = benign_day()
    r = req(base, "POST", "/api/netlog/import", files=[("home-day.ndjson.gz", ndjson(day))])
    print("import", r.get("inserted"), r.get("errors"), [f.get("error") for f in r.get("files", [])])
    a = all_alerts(base)
    core = tally(a, "core benign day (15 devices)")
    nrows, picks = noise_rows(lake)
    r = req(base, "POST", "/api/netlog/import", files=[("plex-noise.ndjson.gz", ndjson(nrows))])
    a = all_alerts(base)
    noise = tally(a, "+ inbound noise on forwarded Plex port from listed IPs")
    prows, listed = p2p_rows(lake)
    r = req(base, "POST", "/api/netlog/import", files=[("p2p.ndjson.gz", ndjson(prows))])
    a = all_alerts(base)
    p2p = tally(a, "+ BitTorrent swarm (8 of 68 peers on blocklists)")
    devs = g(base, "/api/netlog/devices", limit=100)
    print("devices:", len(devs), sorted(d.get("hostnames", [None])[0] if d.get("hostnames") else d["id"] for d in devs))


def phase_reported(base, lake):
    st = g(base, "/api/netlog/status")
    print("reported status:", json.dumps(st.get("reported"), default=str)[:1500])
    r = req(base, "POST", "/api/netlog/import", files=[("reported.ndjson.gz", ndjson(reported_traffic()))])
    print("import", r.get("inserted"), r.get("errors"))
    st = g(base, "/api/netlog/status")
    print("reported status after:", json.dumps(st.get("reported"), default=str)[:2500])
    ivs = g(base, "/api/netlog/indicators", source="reported", limit=500)
    rows = ivs if isinstance(ivs, list) else ivs.get("rows", ivs)
    print("reported intervals:")
    for iv in rows if isinstance(rows, list) else []:
        m = iv.get("meta")
        m = json.loads(m) if isinstance(m, str) else m or {}
        print(f"   {iv['value']:24} {iv['category']:22} start={iv['start']} end={iv['end']} srcs={m.get('sources')} ctx={m.get('context')}")
    a = [x for x in all_alerts(base) if x["source"] == "reported" or x["indicator"] in REP.values()]
    tally(a, "alerts involving reported IOCs")
    sev = {}
    for x in a:
        sev[x["indicator"]] = max(sev.get(x["indicator"], None) or "info", x["severity"], key=lambda s: RANK[s])
    checks = [
        ("prose-only IP is not an indicator", sev.get(REP["prose"]) is None),
        ("single report, last-dot defanged (198.51.100[.]51) -> low", sev.get(REP["single"]) == "low"),
        ("two vendors -> medium", sev.get(REP["two_vendor"]) == "medium"),
        ("syndicated copy of ONE vendor's list stays low", sev.get(REP["syndicated"]) == "low"),
        ("expired report: new contact info, old-window contact low", sev.get(REP["expired"]) in ("low", "info")),
        ("geo claim (no actor/malware) does not count", sev.get(REP["geo_claim"]) is None),
        ("malware claim -> low", sev.get(REP["malware_claim"]) == "low"),
        ("five sources + accepted inbound RDP never high", sev.get(REP["five_src"]) == "medium"),
        ("discord.com never alerts", "discord.com" not in sev),
        ("api.telegram.org never alerts", "api.telegram.org" not in sev),
        ("cdn.discordapp.com never alerts", "cdn.discordapp.com" not in sev),
        ("bing / dropboxapi never alert", "www.bing.com" not in sev and "api.dropboxapi.com" not in sev),
        ("8.8.8.8 and the Cloudflare address are dropped", "8.8.8.8" not in sev and "104.16.101.215" not in sev),
        ("ancient domain (240 d) expired -> info only", sev.get("ancient-c2.example") in (None, "info")),
        ("evil-update.example single -> low", sev.get("evil-update.example") == "low"),
    ]
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    for x in a:
        if x["indicator"] == REP["expired"]:
            print("   expired detail:", x["severity"], x["rule"], x["ts"])
    print("sev:", sev)


def phase_timely(base, lake):
    rows = []
    G = Gen(17)
    G.n = 980000
    for k in range(3):
        G.conn(T("2026-11-03T14:00:00Z") + k * 900, "192.0.2.29", NEW_C2, 443, ob=1800, rb=2200, dur=0.8,
               sni="cdn-sync.example", mac="00:00:5e:00:53:09")
    r = req(base, "POST", "/api/netlog/import", files=[("nas-2days-ago.ndjson.gz", ndjson(G.rows))])
    print("import", r.get("inserted"))
    now = datetime.now(UTC)
    d = lake / "raw" / "feodo_c2" / now.strftime("%Y/%m/%d")
    d.mkdir(parents=True, exist_ok=True)
    f = d / (now.strftime("%H%M%S") + ".records.ndjson.gz")
    rec = {"key": f"{NEW_C2}:443", "op": "put", "data": {"ip_address": NEW_C2, "port": 443, "status": "online",
           "hostname": None, "as_number": 64500, "as_name": "EXAMPLE", "country": "NL",
           "first_seen": "2026-11-01 08:00:00", "last_online": now.strftime("%Y-%m-%d"), "malware": "QakBot"}}
    f.write_bytes(gzip.compress((json.dumps(rec) + "\n").encode()))
    print("delta written", f.relative_to(lake), "at", now.isoformat())
    t0 = time.time()
    hit = None
    while time.time() - t0 < 240:
        a = g(base, "/api/netlog/alerts", indicator=NEW_C2, limit=0)
        if a:
            hit = a
            break
        time.sleep(3)
    lat = time.time() - t0
    if not hit:
        print(f"FAIL no alert after {lat:.0f}s")
        return
    print(f"alert after {lat:.0f}s")
    for x in hit:
        ev = x["evidence"]
        print("  ", x["severity"], x["rule"], "device", x["device"], "uids", ev.get("uid_count"),
              "listing", [(l.get("start_path"), l.get("start")) for l in ev.get("listing", [])],
              "meta first_seen", (ev.get("indicator") or {}).get("meta", {}).get("first_seen") if isinstance((ev.get("indicator") or {}).get("meta"), dict) else (ev.get("indicator") or {}).get("meta"))
    devs = g(base, "/api/netlog/devices", sort="alerts", limit=3)
    nas = [d for d in g(base, "/api/netlog/devices", limit=100) if "192.0.2.29" in (d.get("ips") or [])]
    print("NAS on device list: alerts", [(d["id"], d.get("alerts"), d.get("max_severity")) for d in nas])


def phase_usability(base, lake):
    req(base, "POST", "/api/netlog/import", files=[("problem.ndjson.gz", ndjson(problem_rows()))])
    t0 = time.time()
    devs = g(base, "/api/netlog/devices", sort="alerts", limit=5)
    top = devs[0]
    det = g(base, f"/api/netlog/devices/{urllib.parse.quote(top['id'], safe=':')}")
    print(f"2 calls in {time.time() - t0:.2f}s")
    for d in devs:
        print("  ", d["id"], d.get("hostnames"), d.get("ips"), "alerts", d.get("alerts"), d.get("max_severity"))
    print("detail keys:", sorted(det.keys()))
    for a in (det.get("alerts") or [])[:8]:
        print("    ", a.get("severity"), a.get("rule"), a.get("indicator"), a.get("title"))
    ok = "wyze-cam-garage" in (top.get("hostnames") or []) and top.get("max_severity") == "high"
    print(("PASS " if ok else "FAIL ") + "first device by alerts is the beaconing camera, named, severity high")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8816")
    ap.add_argument("--lake", required=True, type=Path)
    ap.add_argument("--seed", action="store_true")
    ap.add_argument("--phase", choices=["benign", "reported", "timely", "usability"])
    a = ap.parse_args()
    if a.seed:
        seed(a.lake)
    if a.phase:
        globals()["phase_" + a.phase](a.base, a.lake)
