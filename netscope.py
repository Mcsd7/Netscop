#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OFFTEC // NETSCOPE  -  monitor de conexões de rede para Android + Termux (SEM ROOT)

Instalar : pkg install python && pip install rich
Opcional : pkg install termux-api  (+ app Termux:API) para info de Wi-Fi
Rodar    : python netscope.py          (use --no-geo para não consultar geolocalização online)

Uso ético: monitore apenas o seu próprio aparelho.
"""
import os, re, sys, csv, json, time, queue, socket, struct, ipaddress, subprocess, threading
from collections import Counter, defaultdict, deque
from datetime import datetime
from urllib.request import Request, urlopen

try:
    from rich import box
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.markup import escape
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:
    sys.exit("Falta a biblioteca rich ->  pip install rich")

VERSION = "1.0"
G, C, Y, R, D = "bright_green", "cyan", "yellow", "bold red", "grey50"
NO_GEO = "--no-geo" in sys.argv
DATA = os.path.expanduser("~/.netscope")
CUSTOM = os.path.join(DATA, "custom_blocklist.txt")  # um IP ou domínio por linha

SOURCES = [
    ("Feodo Tracker (IPs de C2)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("URLhaus (domínios malware)", "https://urlhaus.abuse.ch/downloads/hostfile/"),
]

SERVICES = {80: "HTTP", 443: "HTTPS", 53: "DNS", 853: "DoT", 123: "NTP", 22: "SSH", 21: "FTP",
            23: "TELNET", 25: "SMTP", 465: "SMTPS", 587: "SMTP", 110: "POP3", 995: "POP3S",
            143: "IMAP", 993: "IMAPS", 3306: "MYSQL", 5432: "PGSQL", 3389: "RDP", 5228: "FCM",
            5222: "XMPP", 1883: "MQTT", 8883: "MQTTS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            161: "SNMP", 389: "LDAP", 636: "LDAPS", 445: "SMB", 5060: "SIP", 1900: "SSDP",
            5353: "MDNS", 69: "TFTP"}
CLEARTEXT = {80, 21, 23, 25, 110, 143, 8080, 161, 389, 69, 5060, 1883}
SUSPECT = {4444: "porta comum de reverse shell", 6667: "IRC (usado por botnets)",
           31337: "porta histórica de backdoor", 1337: "porta 'elite' de backdoor",
           9001: "relay Tor", 9050: "Tor SOCKS", 12345: "porta NetBus"}
TCP_STATES = {"01": "ESTAB", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
              "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
              "0A": "LISTEN", "0B": "CLOSING"}
ACTIVE = ("ESTAB", "ATIVO", "SYN_SENT")


# ───────────────────────────── coleta (sem root) ─────────────────────────────
def hexaddr(s, v6):
    h, port = s.split(":")
    if not v6:
        ip = socket.inet_ntoa(struct.pack("<I", int(h, 16)))
    else:
        raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
        a = ipaddress.IPv6Address(raw)
        ip = str(a.ipv4_mapped) if a.ipv4_mapped else str(a)
    return ip, int(port, 16)


def make_conn(proto, lip, lport, rip, rport, st, uid):
    state = TCP_STATES.get(st, st) if proto == "TCP" else ("ATIVO" if st == "01" and rport else "BIND")
    public = False
    if rport:
        try:
            public = ipaddress.ip_address(rip).is_global
        except ValueError:
            pass
    return dict(proto=proto, lip=lip, lport=lport, rip=rip, rport=rport, state=state, uid=uid,
                public=public, app="", service="", domain="", geo={}, hit=None, cleartext=False)


def parse_proc(path, proto, v6):
    out = []
    with open(path) as f:
        next(f)
        for line in f:
            p = line.split()
            if len(p) < 8:
                continue
            lip, lport = hexaddr(p[1], v6)
            rip, rport = hexaddr(p[2], v6)
            out.append(make_conn(proto, lip, lport, rip, rport, p[3], int(p[7])))
    return out


def read_connections():
    conns, fails = [], 0
    for path, proto, v6 in (("/proc/net/tcp", "TCP", False), ("/proc/net/tcp6", "TCP", True),
                            ("/proc/net/udp", "UDP", False), ("/proc/net/udp6", "UDP", True)):
        try:
            conns += parse_proc(path, proto, v6)
        except Exception:
            fails += 1
    return conns, fails == 4  # (conexões, bloqueado?)


def net_bytes():
    rx = tx = 0
    ok = False
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, data = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                p = data.split()
                rx += int(p[0]); tx += int(p[8]); ok = True
    except Exception:
        pass
    if not ok:
        try:
            base = "/sys/class/net"
            for i in os.listdir(base):
                if i != "lo":
                    rx += int(open(f"{base}/{i}/statistics/rx_bytes").read())
                    tx += int(open(f"{base}/{i}/statistics/tx_bytes").read())
                    ok = True
        except Exception:
            pass
    return (rx, tx) if ok else None


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "—"


def wifi_info():
    try:
        r = subprocess.run(["termux-wifi-connectioninfo"], capture_output=True, text=True, timeout=8)
        d = json.loads(r.stdout)
        return d if "rssi" in d else None
    except Exception:
        return None


# ───────────────────────────── enriquecimento ─────────────────────────────
class Resolver:
    """DNS reverso (PTR) em threads de fundo."""
    def __init__(self, workers=6):
        self.cache, self.pending, self.q = {}, set(), queue.Queue()
        for _ in range(workers):
            threading.Thread(target=self._work, daemon=True).start()

    def get(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        if ip not in self.pending:
            self.pending.add(ip)
            self.q.put(ip)
        return None

    def _work(self):
        while True:
            ip = self.q.get()
            try:
                name = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
                if name == ip:
                    name = ""
            except Exception:
                name = ""
            self.cache[ip] = name
            self.pending.discard(ip)


class GeoIP:
    """Geolocalização/ASN em lote via ip-api.com (consulta online)."""
    def __init__(self):
        self.cache, self.pending, self.lock, self.fail_until = {}, set(), threading.Lock(), 0
        if not NO_GEO:
            threading.Thread(target=self._work, daemon=True).start()

    def busy(self):
        return bool(self.pending) and time.time() >= self.fail_until and not NO_GEO

    def get(self, ip):
        if NO_GEO:
            return {}
        if ip in self.cache:
            return self.cache[ip]
        with self.lock:
            self.pending.add(ip)
        return None

    def _work(self):
        while True:
            time.sleep(1.5)
            if time.time() < self.fail_until:
                continue
            with self.lock:
                batch = list(self.pending)[:100]
                for ip in batch:
                    self.pending.discard(ip)
            if not batch:
                continue
            try:
                url = "http://ip-api.com/batch?fields=status,country,countryCode,city,as,org,query"
                req = Request(url, data=json.dumps(batch).encode(), headers={"Content-Type": "application/json"})
                for r in json.loads(urlopen(req, timeout=8).read()):
                    self.cache[r.get("query")] = r if r.get("status") == "success" else {}
            except Exception:
                self.fail_until = time.time() + 30
                with self.lock:
                    self.pending.update(batch)


def parse_list(text):
    ips, doms = set(), set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        for tok in line.replace(",", " ").split():
            tok = tok.lower()
            if tok in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
                continue
            try:
                ipaddress.ip_address(tok)
                ips.add(tok)
                continue
            except ValueError:
                pass
            if re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.[a-z]{2,}", tok):
                doms.add(tok)
    return ips, doms


class Blocklist:
    def __init__(self):
        self.ips, self.domains = set(), set()
        self.load()

    def files(self):
        return [os.path.join(DATA, f"bl_{i}.txt") for i in range(len(SOURCES))] + [CUSTOM]

    def load(self):
        self.ips, self.domains = set(), set()
        for f in self.files():
            if os.path.exists(f):
                with open(f, errors="ignore") as fh:
                    i, d = parse_list(fh.read())
                self.ips |= i
                self.domains |= d

    def update(self):
        res = []
        for n, (name, url) in enumerate(SOURCES):
            try:
                raw = urlopen(Request(url, headers={"User-Agent": "netscope"}), timeout=25).read().decode("utf-8", "ignore")
                with open(os.path.join(DATA, f"bl_{n}.txt"), "w") as fh:
                    fh.write(raw)
                i, d = parse_list(raw)
                res.append((name, True, f"{len(i)} IPs · {len(d)} domínios"))
            except Exception as e:
                res.append((name, False, type(e).__name__))
        self.load()
        return res

    def check(self, ip, domain=""):
        if ip in self.ips:
            return "IP em blocklist"
        parts = (domain or "").lower().rstrip(".").split(".")
        for k in range(max(0, len(parts) - 1)):
            if ".".join(parts[k:]) in self.domains:
                return "domínio em blocklist"
        return None


class Engine:
    def __init__(self):
        self.resolver, self.geo, self.bl, self.uidmap = Resolver(), GeoIP(), Blocklist(), {}
        threading.Thread(target=self._uids, daemon=True).start()

    def _uids(self):
        try:  # só funciona em alguns aparelhos; sem isso mostramos o UID
            out = subprocess.run(["pm", "list", "packages", "-U"], capture_output=True, text=True, timeout=8).stdout
            for line in out.splitlines():
                m = re.match(r"package:(\S+)\s+uid:(\d+)", line)
                if m:
                    self.uidmap.setdefault(int(m.group(2)), m.group(1))
        except Exception:
            pass

    def app(self, uid):
        if uid == os.getuid():
            return "termux"
        if uid in self.uidmap:
            return self.uidmap[uid]
        return f"u0_a{uid - 10000}" if uid >= 10000 else str(uid)

    def pending(self):
        return len(self.resolver.pending) + (len(self.geo.pending) if self.geo.busy() else 0)

    def enrich(self, c):
        c["app"] = self.app(c["uid"])
        port = c["rport"] or c["lport"]
        c["service"] = "QUIC" if (c["proto"] == "UDP" and port == 443) else SERVICES.get(port, "")
        if c["public"]:
            c["domain"] = self.resolver.get(c["rip"])
            c["geo"] = self.geo.get(c["rip"])
            c["hit"] = self.bl.check(c["rip"], c["domain"] or "")
            c["cleartext"] = c["rport"] in CLEARTEXT

    def snapshot(self):
        conns, blocked = read_connections()
        for c in conns:
            self.enrich(c)
        return conns, blocked


# ───────────────────────────── helpers de visual ─────────────────────────────
def header():
    t = Text()
    t.append("  OFFTEC // NETSCOPE ", style=f"bold {G}")
    t.append(VERSION, style=f"bold {C}")
    t.append("\n  NET MONITOR // ANDROID · NO ROOT", style=C)
    return Panel(t, box=box.ROUNDED, border_style=G)


def panel(body, title, color=C):
    return Panel(body, title=f"[bold {color}]{title}[/]", box=box.ROUNDED, border_style=color)


def spark(vals, width=30):
    bars, vals = "▁▂▃▄▅▆▇█", list(vals)[-width:]
    hi = max(vals) if vals and max(vals) else 1
    return "".join(bars[min(7, int(v / hi * 7))] for v in vals)


def bar(frac, width=22, color=G):
    n = max(0, min(width, int(frac * width)))
    return Text("█" * n, style=color) + Text("░" * (width - n), style=D)


def fmt_rate(b):
    for u in ("B/s", "KB/s", "MB/s"):
        if b < 1024:
            return f"{b:.0f} {u}" if u == "B/s" else f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} GB/s"


def fmt_size(b):
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.0f} {u}" if u == "B" else f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"


def dest(c):
    if not c["rport"]:
        return f"*:{c['lport']}"
    return f"{c.get('domain') or c['rip']}:{c['rport']}"


def cc(c):
    if not c["public"]:
        return "LAN" if c["rport"] else ""
    g = c["geo"]
    return "…" if g is None else (g.get("countryCode") or "-")


def row_style(c):
    if c["hit"]:
        return R
    if c["cleartext"]:
        return Y
    if c["state"] in ACTIVE:
        return G
    return C if c["state"] == "LISTEN" else D


def conn_table(conns, narrow):
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {C}", border_style=D, expand=True, pad_edge=False)
    t.add_column("PRT", width=3, no_wrap=True)
    if not narrow:
        t.add_column("LOCAL", no_wrap=True, overflow="ellipsis", max_width=22)
    t.add_column("DESTINO", ratio=1, no_wrap=True, overflow="ellipsis")
    if not narrow:
        t.add_column("ESTADO", no_wrap=True)
    t.add_column("SERV", no_wrap=True, max_width=8)
    t.add_column("PA", no_wrap=True, width=3)
    if not narrow:
        t.add_column("APP", no_wrap=True, overflow="ellipsis", max_width=22)
    for c in conns:
        st = row_style(c)
        mark = "⚠ " if c["hit"] else ("! " if c["cleartext"] else "")
        cells = [c["proto"]]
        if not narrow:
            cells.append(f"{c['lip']}:{c['lport']}")
        cells.append(mark + dest(c))
        if not narrow:
            cells.append(c["state"])
        cells += [c["service"], cc(c)]
        if not narrow:
            cells.append(c["app"])
        t.add_row(*[Text(str(x), style=st, no_wrap=True, overflow="ellipsis") for x in cells])
    return t


def pause(console):
    try:
        console.input(f"\n[{D}]ENTER para voltar…[/]")
    except (EOFError, KeyboardInterrupt):
        pass


def collect(console, engine, wait=6):
    with console.status(f"[{C}]coletando e resolvendo destinos…", spinner="dots"):
        engine.snapshot()
        t0 = time.time()
        while engine.pending() and time.time() - t0 < wait:
            time.sleep(0.4)
        return engine.snapshot()


def blocked_msg(console):
    console.print(panel(
        "[yellow]Não consegui ler /proc/net/* neste aparelho.[/]\n\n"
        "O Android 10+ bloqueia isso para apps recentes. Tente a versão do Termux do "
        "F-Droid/GitHub (build antiga, targetSdk 28) ou use o PCAPdroid em paralelo.", "ACESSO BLOQUEADO", "yellow"))


def analyze(conns):
    out, seen = [], set()
    cnt = Counter(c["rip"] for c in conns if c["public"])
    rank = {"ALTO": 0, "MÉDIO": 1, "BAIXO": 2}

    def add(sev, title, detail):
        if (sev, title, detail) not in seen:
            seen.add((sev, title, detail))
            out.append((sev, title, detail))

    for c in conns:
        who = f"{dest(c)} · {c['app']}"
        if c["state"] == "LISTEN" and c["lip"] in ("0.0.0.0", "::"):
            add("MÉDIO", "Porta TCP exposta na rede", f"*:{c['lport']} · {c['app']}")
        if not c["public"]:
            continue
        if c["hit"]:
            add("ALTO", "Destino em blocklist", f"{who} · {c['hit']}")
        if c["cleartext"]:
            add("MÉDIO", "Tráfego sem criptografia", f"{who} · {c['service']}")
        if c["rport"] in SUSPECT:
            add("MÉDIO", "Porta suspeita", f"{who} · {SUSPECT[c['rport']]}")
        if c["rport"] == 53:
            add("BAIXO", "DNS sem criptografia", who)
        if cnt[c["rip"]] >= 20:
            add("BAIXO", "Muitas conexões ao mesmo IP", f"{c['rip']} · {cnt[c['rip']]} conexões")
    return sorted(out, key=lambda x: rank[x[0]])


# ───────────────────────────── monitor ao vivo ─────────────────────────────
def build_monitor(console, engine, conns, blocked, hist, rate):
    w, h = console.size
    narrow = w < 75
    ext = [c for c in conns if c["public"] and c["state"] in ACTIVE]
    ext.sort(key=lambda c: (not c["hit"], not c["cleartext"], dest(c)))
    n_listen = sum(1 for c in conns if c["state"] == "LISTEN")
    n_clear = sum(1 for c in ext if c["cleartext"])
    n_hit = sum(1 for c in ext if c["hit"])

    g = Table.grid(expand=True, padding=(0, 1))
    g.add_column(style=C, no_wrap=True); g.add_column(justify="right"); g.add_column(style=C, no_wrap=True); g.add_column(justify="right")
    num = lambda v, st: Text(str(v), style=st)
    g.add_row("ATIVAS", num(len(ext), f"bold {G}"), "DESTINOS", num(len({c['rip'] for c in ext}), f"bold {G}"))
    g.add_row("ESCUTA", num(n_listen, f"bold {G}"), "TXT CLARO", num(n_clear, f"bold {Y if n_clear else G}"))
    g.add_row("BLOCKLIST", num(n_hit, R if n_hit else f"bold {G}"), "UDP", num(sum(1 for c in conns if c['proto'] == 'UDP'), f"bold {G}"))
    rates = f"↓ {fmt_rate(rate[0])}  ↑ {fmt_rate(rate[1])}" if rate else "n/d"
    stats = Group(g, Text.assemble(("REDE  ", C), (rates, G)), Text.assemble(("ATIV  ", C), (spark(hist), G)))

    if blocked:
        body = Text("Sem acesso a /proc/net (Android bloqueou). Veja opção 'i'.", style="yellow")
    else:
        limit = max(3, h - 4 - 7 - 3 - 4)
        body = conn_table(ext[:limit], narrow)

    st = f"● Monitorando │ {datetime.now():%H:%M:%S} │ 2s │ Ctrl+C voltar"
    if engine.pending():
        st = f"● Resolvendo {engine.pending()} destinos… │ Ctrl+C voltar"
    lay = Layout()
    lay.split_column(Layout(header(), size=4), Layout(panel(stats, "ESTATÍSTICAS"), size=7),
                     Layout(panel(body, "CONEXÕES ATIVAS")),
                     Layout(Panel(Text(st, style=G), box=box.ROUNDED, border_style=D), size=3))
    return lay


def monitor(console, engine):
    hist, rate = deque(maxlen=40), None
    prev, tprev = net_bytes(), time.time()
    try:
        with Live(console=console, screen=True, auto_refresh=False) as live:
            while True:
                conns, blocked = engine.snapshot()
                now, cur = time.time(), net_bytes()
                if prev and cur and now > tprev:
                    rate = ((cur[0] - prev[0]) / (now - tprev), (cur[1] - prev[1]) / (now - tprev))
                prev, tprev = cur, now
                hist.append(sum(1 for c in conns if c["state"] in ACTIVE))
                live.update(build_monitor(console, engine, conns, blocked, hist, rate), refresh=True)
                time.sleep(2)
    except KeyboardInterrupt:
        pass


# ───────────────────────────── telas do menu ─────────────────────────────
def screen_connections(console, engine):
    conns, blocked = collect(console, engine)
    if blocked:
        return blocked_msg(console)
    rank = {"ESTAB": 0, "ATIVO": 0, "SYN_SENT": 1, "LISTEN": 2}
    conns.sort(key=lambda c: (not c["hit"], rank.get(c["state"], 3), dest(c)))
    shown = conns[:60]
    console.print(panel(conn_table(shown, console.size.width < 75), f"CONEXÕES · {len(conns)}"))
    if len(conns) > 60:
        console.print(f"[{D}]… mostrando 60 de {len(conns)}. Use a opção 8 para exportar tudo.[/]")
    console.print(f"[{D}]⚠ blocklist   ! texto claro   PA = país   APP = UID/pacote[/]")


def screen_domains(console, engine):
    conns, blocked = collect(console, engine)
    if blocked:
        return blocked_msg(console)
    grp = defaultdict(lambda: {"n": 0, "serv": set(), "cc": set(), "hit": False})
    for c in conns:
        if c["public"]:
            k = grp[c.get("domain") or c["rip"]]
            k["n"] += 1
            k["serv"].add(c["service"] or str(c["rport"]))
            k["cc"].add(cc(c))
            k["hit"] = k["hit"] or bool(c["hit"])
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {C}", border_style=D, expand=True, pad_edge=False)
    t.add_column("DOMÍNIO / IP", ratio=1, no_wrap=True, overflow="ellipsis")
    t.add_column("N", justify="right", width=3)
    t.add_column("SERV", no_wrap=True, max_width=10, overflow="ellipsis")
    t.add_column("PA", width=3)
    for name, k in sorted(grp.items(), key=lambda x: -x[1]["n"])[:60]:
        st = R if k["hit"] else G
        t.add_row(Text(("⚠ " if k["hit"] else "") + name, style=st, no_wrap=True, overflow="ellipsis"),
                  str(k["n"]), ",".join(sorted(k["serv"])), ",".join(sorted(x for x in k["cc"] if x)))
    console.print(panel(t, f"DOMÍNIOS · {len(grp)}"))
    console.print(f"[{D}]Nome vem de DNS reverso (PTR): CDNs podem aparecer sem nome ou com nome genérico.[/]")


def screen_geo(console, engine):
    conns, blocked = collect(console, engine, wait=10)
    if blocked:
        return blocked_msg(console)
    grp = {}
    for c in conns:
        if c["public"]:
            grp.setdefault(c["rip"], [c, 0])[1] += 1
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {C}", border_style=D, expand=True, pad_edge=False)
    t.add_column("IP", no_wrap=True, overflow="ellipsis", max_width=18)
    t.add_column("LOCAL", no_wrap=True, overflow="ellipsis", max_width=16)
    t.add_column("ASN / OPERADORA", ratio=1, no_wrap=True, overflow="ellipsis")
    t.add_column("N", justify="right", width=3)
    got = 0
    for ip, (c, n) in sorted(grp.items(), key=lambda x: -x[1][1])[:60]:
        g = c["geo"] or {}
        got += bool(g)
        loc = ", ".join(x for x in (g.get("city"), g.get("countryCode")) if x) or "-"
        t.add_row(ip, loc, g.get("as") or g.get("org") or "-", str(n))
    console.print(panel(t, f"GEOLOCALIZAÇÃO & ASN · {len(grp)} IPs"))
    if NO_GEO:
        console.print(f"[yellow]Geolocalização desativada (--no-geo).[/]")
    elif grp and not got:
        console.print("[yellow]Sem resposta do serviço de geolocalização (sem internet?).[/]")


def screen_blocklist(console, engine):
    bl = engine.bl
    t = Table.grid(padding=(0, 2))
    t.add_column(style=C); t.add_column(style=G)
    t.add_row("IPs carregados", f"{len(bl.ips):,}")
    t.add_row("Domínios carregados", f"{len(bl.domains):,}")
    t.add_row("Lista própria", CUSTOM.replace(os.path.expanduser("~"), "~"))
    for name, _ in SOURCES:
        t.add_row("Fonte", name)
    console.print(panel(t, "BLOCKLIST"))
    if not (bl.ips or bl.domains):
        console.print(f"[yellow]Listas vazias. Use a opção 9 para baixar.[/]")
    conns, blocked = collect(console, engine)
    hits = [c for c in conns if c["hit"]]
    if hits:
        console.print(panel(conn_table(hits, console.size.width < 75), f"⚠ {len(hits)} CONEXÕES EM BLOCKLIST", "red"))
    elif not blocked:
        console.print(f"[{G}]✔ Nenhuma conexão atual bate com as listas carregadas.[/]")
    try:
        q = console.input(f"\n[{C}]Checar IP/domínio manualmente (ENTER pula):[/] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if q:
        r = bl.check(q, q)
        console.print(f"[{R}]⚠ {escape(q)}: {r}[/]" if r else f"[{G}]✔ {escape(q)}: não consta nas listas.[/]")


def screen_risk(console, engine):
    conns, blocked = collect(console, engine)
    if blocked:
        return blocked_msg(console)
    finds = analyze(conns)
    col = {"ALTO": R, "MÉDIO": f"bold {Y}", "BAIXO": f"bold {C}"}
    if not finds:
        console.print(panel(f"[{G}]✔ Nenhum indício nas conexões atuais.[/]\n[{D}]Verificação por listas e portas; não é garantia de segurança.[/]", "ANÁLISE DE RISCO"))
        return
    t = Table(box=box.SIMPLE_HEAD, header_style=f"bold {C}", border_style=D, expand=True, pad_edge=False)
    t.add_column("NÍVEL", no_wrap=True)
    t.add_column("ACHADO", ratio=1)
    for sev, title, detail in finds[:40]:
        t.add_row(Text(sev, style=col[sev]), Text.assemble((title + "\n", "white"), (detail, D)))
    console.print(panel(t, f"ANÁLISE DE RISCO · {len(finds)}"))


def screen_net(console, engine):
    ip = local_ip()
    t = Table.grid(padding=(0, 2))
    t.add_column(style=C); t.add_column()
    t.add_row("Estado", Text("CONECTADO" if ip != "—" else "OFFLINE", style=G if ip != "—" else R))
    t.add_row("IP local", ip)
    w = wifi_info()
    if w:
        ssid = str(w.get("ssid", ""))
        t.add_row("SSID", ssid)
        t.add_row("BSSID", str(w.get("bssid", "")))
        f = int(w.get("frequency_mhz") or 0)
        ch = (f - 2407) // 5 if 2412 <= f <= 2472 else 14 if f == 2484 else (f - 5000) // 5 if 5000 <= f <= 5895 else (f - 5950) // 5 if f >= 5955 else "?"
        t.add_row("Frequência", f"{f} MHz")
        t.add_row("Canal", str(ch))
        t.add_row("Link Wi-Fi", f"{w.get('link_speed_mbps', '?')} Mbps")
        r = int(w["rssi"])
        lab, colr = next(((l, c) for lim, l, c in ((-50, "Excelente", G), (-60, "Muito bom", G), (-70, "Bom", C), (-80, "Fraco", Y)) if r >= lim), ("Muito fraco", "red"))
        t.add_row("RSSI", Text.assemble((f"{r} dBm  ", "white"), (lab, colr)))
        t.add_row("Sinal", bar((r + 90) / 60, color=colr))
        if "unknown" in ssid.lower():
            t.add_row("", Text("Dica: ative a localização p/ o Android revelar o SSID", style=D))
    else:
        t.add_row("Wi-Fi", Text("termux-api indisponível (pkg install termux-api + app Termux:API)", style=D))
    nb = net_bytes()
    if nb:
        t.add_row("Total ↓", fmt_size(nb[0]))
        t.add_row("Total ↑", fmt_size(nb[1]))
    console.print(panel(t, "INFORMAÇÕES DA REDE"))


def screen_export(console, engine):
    conns, blocked = collect(console, engine)
    if blocked:
        return blocked_msg(console)
    base = os.path.expanduser("~/storage/downloads")
    base = os.path.join(base if os.path.isdir(base) else os.path.expanduser("~"), "netscope_exports")
    os.makedirs(base, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rows = []
    for c in conns:
        g = c["geo"] or {}
        rows.append({"proto": c["proto"], "local": f"{c['lip']}:{c['lport']}",
                     "remote": f"{c['rip']}:{c['rport']}" if c["rport"] else "", "state": c["state"],
                     "service": c["service"], "app": c["app"], "uid": c["uid"], "domain": c["domain"] or "",
                     "country": g.get("country", ""), "city": g.get("city", ""), "asn": g.get("as", ""),
                     "blocklist": c["hit"] or "", "cleartext": c["cleartext"]})
    pj, pc = os.path.join(base, f"netscope_{ts}.json"), os.path.join(base, f"netscope_{ts}.csv")
    with open(pj, "w") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    with open(pc, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["proto"])
        w.writeheader()
        w.writerows(rows)
    console.print(panel(f"[{G}]✔ {len(rows)} conexões exportadas[/]\n[white]{escape(pj)}\n{escape(pc)}[/]\n"
                        f"[{D}]PCAP não é possível sem VPN/root.[/]", "EXPORTAR"))


def screen_update(console, engine):
    with console.status(f"[{C}]baixando blocklists…", spinner="dots"):
        res = engine.bl.update()
    t = Table.grid(padding=(0, 2))
    t.add_column(); t.add_column()
    for name, ok, info in res:
        t.add_row(Text(name, style="white"), Text(("✔ " if ok else "✘ ") + info, style=G if ok else R))
    console.print(panel(t, "ATUALIZAR LISTAS"))
    console.print(f"[{D}]Dica: adicione seus próprios IPs/domínios em {escape(CUSTOM)}[/]")


def screen_limits(console, engine):
    txt = (
        "[bold white]O que NÃO dá para fazer sem root:[/]\n"
        f"[{R}]✘[/] Captura de pacotes / PCAP  [{D}](exige VPN local ou root)[/]\n"
        f"[{R}]✘[/] DPI e decifrar TLS  [{D}](protocolo é estimado pela porta)[/]\n"
        f"[{R}]✘[/] Firewall / bloqueio  [{D}](exige VPN local)[/]\n"
        f"[{R}]✘[/] Bytes por conexão  [{D}](só total da interface)[/]\n\n"
        "[bold white]Como funciona aqui:[/]\n"
        f"[{G}]•[/] Lê /proc/net (pode ser bloqueado no Android 10+)\n"
        f"[{G}]•[/] Domínio = DNS reverso (PTR), não o SNI do TLS\n"
        f"[{G}]•[/] App = UID; nome do pacote só se o aparelho permitir\n"
        f"[{G}]•[/] Geo usa ip-api.com: os IPs de destino saem do aparelho. Use [bold]--no-geo[/] p/ desativar\n\n"
        f"[{C}]Use o PCAPdroid junto: ele captura, o NetScope analisa e exporta.[/]")
    console.print(panel(txt, "LIMITAÇÕES"))


# ───────────────────────────── menu principal ─────────────────────────────
MENU = [
    ("1", "Monitor ao vivo", "tempo real", monitor),
    ("2", "Conexões", "TCP/UDP e apps", screen_connections),
    ("3", "Domínios", "DNS reverso", screen_domains),
    ("4", "Geolocalização & ASN", "país e operadora", screen_geo),
    ("5", "Blocklist", "IPs/domínios maus", screen_blocklist),
    ("6", "Análise de risco", "texto claro etc", screen_risk),
    ("7", "Rede & Wi-Fi", "IP, sinal, tráfego", screen_net),
    ("8", "Exportar", "JSON + CSV", screen_export),
    ("9", "Atualizar listas", "baixar listas", screen_update),
    ("i", "Limitações", "exige root", screen_limits),
    ("0", "Sair", "", None),
]


def draw_menu(console, engine):
    console.clear()
    console.print(header())
    t = Table.grid(padding=(0, 1), expand=True)
    t.add_column(width=3, style=f"bold {G}"); t.add_column(style="white", no_wrap=True); t.add_column(style=D, no_wrap=True, overflow="ellipsis")
    for k, name, desc, _ in MENU:
        t.add_row(f"{k}»", name, desc)
    console.print(panel(t, "MENU"))
    st = Text(f"● Pronto │ {datetime.now():%H:%M:%S} │ {local_ip()}", style=G)
    console.print(Panel(st, box=box.ROUNDED, border_style=D))
    bl = engine.bl
    msg = f"listas: {len(bl.ips):,} IPs · {len(bl.domains):,} dom" if (bl.ips or bl.domains) else "listas vazias → opção 9"
    console.print(f"[{D}] {msg}[/]")


def main():
    os.makedirs(DATA, exist_ok=True)
    console = Console()
    engine = Engine()
    actions = {m[0]: m[3] for m in MENU}
    try:
        while True:
            draw_menu(console, engine)
            ch = Prompt.ask(f"[{G}]netscope[/][{C}] ›[/]", choices=list(actions), show_choices=False, console=console)
            if ch == "0":
                break
            if ch != "1":
                console.clear()
                console.print(header())
            actions[ch](console, engine)
            if ch != "1":
                pause(console)
    except (KeyboardInterrupt, EOFError):
        pass
    console.print(f"\n[{G}]até a próxima · Offtec[/]")


if __name__ == "__main__":
    main()
