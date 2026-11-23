"""Critic audit: compare stored article text/metadata with the stored HTML for a random sample.
    python3 news_extract_audit.py <all.json from /api/news/articles/{id}> <lake> [n] [seed]"""
import gzip, json, random, re, sys, html as H
from pathlib import Path
arts = json.load(open(sys.argv[1])); lake = Path(sys.argv[2])
n = int(sys.argv[3]) if len(sys.argv) > 3 else 20; seed = int(sys.argv[4]) if len(sys.argv) > 4 else 1105
ok = [a for a in arts.values() if a["status"] == "ok" and a.get("html_path")]
random.Random(seed).shuffle(ok)
JUNK = re.compile(r"(cookie|newsletter|subscribe|related (posts|articles|stories)|you may also like|read more|share this|advertis|"
                  r"all rights reserved|sign up|follow us|recommended|trending|popular (posts|stories)|leave a (reply|comment)|"
                  r"about the author|tags:|filed under|webinar|register now|download (the|our)|sponsored)", re.I)
def meta(h, *names):
    for nm in names:
        m = re.search(r'<meta[^>]+(?:property|name)=["\']%s["\'][^>]*content=["\']([^"\']*)' % re.escape(nm), h, re.I) or \
            re.search(r'<meta[^>]+content=["\']([^"\']*)["\'][^>]*(?:property|name)=["\']%s["\']' % re.escape(nm), h, re.I)
        if m: return H.unescape(m.group(1))
def ld(h, key):
    m = re.search(r'"%s"\s*:\s*"([^"]+)"' % key, h); return m.group(1) if m else None
def ld_author(h):
    m = re.search(r'"author"\s*:\s*(\[?\s*\{[^}]*?"name"\s*:\s*"([^"]+)")', h)
    return m.group(2) if m else None
for a in ok[:n]:
    h = gzip.decompress((lake / a["html_path"]).read_bytes()).decode("utf-8", "replace")
    t = a["text"] or ""
    paras = [p for p in t.split("\n") if p.strip()]
    junk = [p[:90] for p in paras if JUNK.search(p) and len(p) < 200]
    page_date = ld(h, "datePublished") or meta(h, "article:published_time")
    page_author = ld_author(h) or meta(h, "author", "article:author")
    # truncation heuristic: page's visible paragraph count vs stored
    page_ps = len(re.findall(r"<p[\s>]", h))
    print(json.dumps({"id": a["id"], "src": a["source"], "url": a["url"], "chars": len(t), "paras": len(paras), "page_<p>": page_ps,
                      "pub_stored": str(a["published"])[:19], "pub_page": page_date, "author_stored": a.get("author"),
                      "author_page": page_author, "junk_lines": junk[:6], "last": paras[-1][:160] if paras else ""}, ensure_ascii=False))
