"""High-precision textual cues for ATT&CK techniques (tool names, commands, artefacts).

A small, general dictionary in the spirit of TRAM-style cue matching: each pattern names a
concrete artefact (a command line, a Windows binary, a registry location) that implies one
technique on its own. It complements the LLM, which finds behaviour described in prose, and
it works offline. Each hit keeps the matched sentence as its evidence quote.
"""
from __future__ import annotations

import re

# (technique id, regex). Case-insensitive, word-bounded where it matters.
CUES: list[tuple[str, str]] = [
    ("T1059.001", r"\bpowershell(?:\.exe)?\b.{0,40}\b(?:-enc|-encodedcommand|-e |-nop|-w hidden|iex|invoke-)|\bpowershell (?:script|command)s?\b"),
    ("T1059.003", r"\bcmd(?:\.exe)? /c\b|\bwindows command shell\b|\bbatch (?:file|script)s?\b|\.bat\b"),
    ("T1059.005", r"\bvbscript\b"),
    ("T1059.007", r"\bjscript\b|\bwscript(?:\.exe)?\b.{0,30}\.js\b"),
    ("T1053.005", r"\bscheduled tasks?\b|\bschtasks(?:\.exe)?\b"),
    ("T1047", r"\bwmic(?:\.exe)?\b|\bwindows management instrumentation\b|\bwmiprvse\b"),
    ("T1218.011", r"\brundll32(?:\.exe)?\b"),
    ("T1218.005", r"\bmshta(?:\.exe)?\b"),
    ("T1218.007", r"\bmsiexec(?:\.exe)?\b"),
    ("T1003.001", r"\blsass(?:\.exe)?\b.{0,40}\b(?:dump|memory|access)|\bmimikatz\b|\bsekurlsa\b|\bprocdump\b.{0,30}lsass"),
    ("T1003.003", r"\bntds\.dit\b"),
    ("T1558.003", r"\bkerberoast"),
    ("T1550.002", r"\bpass[- ]the[- ]hash\b"),
    ("T1021.001", r"\b(?:rdp|remote desktop)\b.{0,40}\b(?:session|connection|login|logon|lateral|access)|\bmstsc\b"),
    ("T1021.002", r"\badmin\$|\bc\$\\|\bsmb\b.{0,40}\b(?:lateral|copied|share|transfer)"),
    ("T1569.002", r"\bpsexec(?:svc)?\b|\bservice execution\b|\bsc(?:\.exe)? (?:create|start)\b"),
    ("T1543.003", r"\b(?:new|malicious|created an?|installed (?:a|as a)) (?:windows )?service\b|\bsc(?:\.exe)? create\b"),
    ("T1547.001", r"\\currentversion\\run\b|\brun keys?\b|\bstartup folder\b"),
    ("T1482", r"\bnltest\b.{0,30}domain_trusts|\bdomain trusts?\b|\btrustdmp\b"),
    ("T1087.002", r"\badfind\b|\bnet user\b.{0,20}/domain|\bdomain (?:user )?accounts? (?:enumeration|discovery)"),
    ("T1069.002", r"\bnet group\b.{0,40}/domain|\bdomain admins\b.{0,40}\b(?:group|enumerat|query)"),
    ("T1018", r"\bnet view\b|\bremote system discovery\b|\bping(?:ed)? (?:sweep|hosts|machines|systems)"),
    ("T1016", r"\bipconfig\b|\broute print\b|\barp -a\b"),
    ("T1082", r"\bsysteminfo\b|\bsystem information (?:discovery|collection)\b"),
    ("T1033", r"\bwhoami\b"),
    ("T1057", r"\btasklist\b|\bprocess (?:list|enumeration|discovery)\b"),
    ("T1135", r"\bnet share\b|\bnetwork shares? (?:discovery|enumerat)|\bshare enumeration\b"),
    ("T1046", r"\b(?:advanced ip scanner|softperfect|netscan|nmap|masscan|port scan)"),
    ("T1518.001", r"\bsecurity software discovery\b|\b(?:enumerat|check|quer)\w* (?:for )?(?:installed )?(?:antivirus|av products|security products)"),
    ("T1219", r"\b(?:anydesk|teamviewer|screenconnect|connectwise|atera|splashtop|netsupport|rustdesk|remote utilities|simplehelp|meshagent)\b"),
    ("T1567.002", r"\brclone\b|\bmega(?:\.nz|sync)\b|exfiltrat\w+ .{0,40}\bcloud storage\b"),
    ("T1486", r"\bencrypt(?:ed|s|ing)? (?:the )?(?:files|data|systems|hosts)\b|\bransom note\b"),
    ("T1490", r"\bvssadmin\b|\bshadow cop(?:y|ies)\b|\bwbadmin\b|\bbcdedit\b"),
    ("T1070.004", r"\b(?:deleted|removes?|removed|deletes) (?:itself|the (?:file|dropper|payload|binary)s?)\b|\bself-delet"),
    ("T1070.001", r"\bwevtutil\b.{0,20}\bcl\b|\bclear(?:ed|s)? (?:the )?(?:windows )?event logs?\b"),
    ("T1055", r"\bprocess (?:injection|hollowing)\b|\binject(?:s|ed|ing)? (?:itself |code |shellcode |a dll )?into\b"),
    ("T1574.002", r"\bdll side-?loading\b|\bside-?load(?:s|ed|ing)?\b"),
    ("T1574.001", r"\bdll search order hijack"),
    ("T1140", r"\bdeobfuscat\w+\b|\bdecrypts? (?:the |its )?(?:embedded |next-stage |final )?(?:payload|shellcode|configuration)\b"),
    ("T1027", r"\bobfuscat(?:ed|ion|es)\b"),
    ("T1105", r"\b(?:download(?:s|ed)?|retriev\w+|fetch\w*) (?:additional|further|next-stage|second-stage|more) (?:payloads?|malware|tools|components|stages?)\b|\bcertutil\b.{0,30}urlcache|\bbitsadmin\b"),
    ("T1071.001", r"\bhttps? (?:requests?|traffic|post|get|protocol)\b.{0,60}\bc(?:&|2|ommand and control)|\bc(?:&|2)\b.{0,40}\bover https?\b|\bweb protocols?\b"),
    ("T1071.004", r"\bdns tunnel|\bc(?:&|2)\b.{0,40}\bover dns\b"),
    ("T1573", r"\bencrypted (?:c(?:&|2)|channel|communication)"),
    ("T1041", r"\bexfiltrat\w+\b.{0,50}\b(?:over|via|through) (?:the |its )?(?:c(?:&|2)|command and control)"),
    ("T1113", r"\bscreenshots?\b|\bscreen captures?\b"),
    ("T1056.001", r"\bkeylog"),
    ("T1115", r"\b(?:steal|monitor|captur|collect|read|grab|hijack)\w* (?:the )?(?:victim's )?clipboard\b|\bclipboard (?:data|contents|monitoring|stealing)\b"),
    ("T1555.003", r"\b(?:browser|chrome|firefox|edge)\b.{0,30}\b(?:credentials|passwords|login data|cookies)\b"),
    ("T1566.001", r"\b(?:spear)?phishing (?:email|e-mail|message)s?\b.{0,60}\battach|\bmalicious attachments?\b|\bspearphishing attachment\b"),
    ("T1566.002", r"\b(?:spear)?phishing (?:email|e-mail|message)s?\b.{0,60}\blinks?\b|\bspearphishing link\b"),
    ("T1204.002", r"\b(?:user|victim)s? (?:opened|opens|executed|executes|double-clicked|clicked)\b|\bwhen (?:opened|executed) by the (?:user|victim)\b"),
    ("T1190", r"\bexploit(?:ed|ing|ation of)?\b.{0,60}\b(?:public-facing|internet-facing|web server|vpn|gateway|confluence|exchange|sharepoint|citrix|netscaler|fortigate|ivanti)\b"),
    ("T1078", r"\bvalid (?:accounts?|credentials)\b|\bcompromised (?:accounts?|credentials)\b"),
    ("T1136.001", r"\bnet user\b.{0,40}/add\b|\bcreated? (?:a )?(?:new )?local (?:admin(?:istrator)? )?account"),
    ("T1560.001", r"\b(?:winrar|7-?zip|rar\.exe)\b.{0,40}\b(?:archive|compress|password)"),
    ("T1102", r"\b(?:telegram|discord|slack|dropbox|google drive|onedrive|github|pastebin|microsoft graph)\b.{0,40}\b(?:c(?:&|2)|command and control|dead drop)"),
    ("T1090", r"\b(?:socks|reverse proxy|proxy tool|tunnel(?:ing|s)? tool)\b"),
    ("T1572", r"\b(?:ngrok|chisel|plink|cloudflared|devtunnels?|ssh tunnel)\b"),
    ("T1037", r"\blogon scripts?\b"),
    ("T1620", r"\breflective(?:ly)? (?:load|dll)"),
    ("T1497", r"\banti-?(?:vm|sandbox|analysis)\b|\bsandbox evasion\b|\bvirtualization checks?\b"),
    ("T1622", r"\banti-?debug"),
    ("T1014", r"\brootkit\b"),
    ("T1068", r"\bprivilege escalation (?:vulnerability|exploit)\b|\bexploit(?:ed|s)? .{0,30}to (?:escalate|gain system)"),
    ("T1548.002", r"\buac bypass\b|\bbypass(?:es|ed)? (?:the )?(?:user account control|uac)\b"),
    ("T1588.002", r"\b(?:open-source|publicly available|commercial|cracked) (?:tools?|frameworks?|red team)"),
    ("T1583.001", r"\b(?:registered|purchased|acquired) (?:the )?domains?\b"),
    ("T1505.003", r"\bweb ?shells?\b"),
    ("T1036.005", r"\bmasquerad\w+ as (?:a )?legitimate\b"),
    ("T1036", r"\bmasquerad"),
]
_COMPILED = [(t, re.compile(p, re.I | re.S)) for t, p in CUES]


def cue_techniques(text: str) -> dict[str, str]:
    """{technique id: verbatim sentence containing the cue}."""
    out: dict[str, str] = {}
    for tid, rx in _COMPILED:
        m = rx.search(text)
        if not m:
            continue
        a = max(text.rfind(".", 0, m.start()), text.rfind("\n", 0, m.start())) + 1
        b = min([x for x in (text.find(".", m.end()), text.find("\n", m.end())) if x >= 0] or [len(text)])
        out[tid] = re.sub(r"\s+", " ", text[a:b]).strip()[:300]
    return out
