#!/usr/bin/env python3
"""IP Globe : serveur local qui expose les connexions réseau de ce PC (géolocalisées hors ligne)
et permet de les couper ou de bloquer une IP (avec mot de passe administrateur via pkexec)."""
import ipaddress, json, os, re, secrets, socket, subprocess, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import maxminddb

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 8765
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}   # bloque le « DNS rebinding » depuis un site web
TOKEN = secrets.token_urlsafe(32)                            # exigé pour toute action : un autre site ne peut pas le lire
CITY = maxminddb.open_database(os.path.join(HERE, "dbip-city-lite.mmdb"))
ASN = maxminddb.open_database(os.path.join(HERE, "dbip-asn-lite.mmdb"))
BLOCKED_FILE = os.path.join(HERE, "blocked.json")
USERS = re.compile(r'"([^"]+)",pid=(\d+)')
TCPINFO = re.compile(r"\b(rtt|bytes_sent|bytes_received|lastsnd|lastrcv):([\d.]+)")
POOL = ThreadPoolExecutor(4)
NFT_TABLE = "inet ipglobe"


def boot_id():
    with open("/proc/sys/kernel/random/boot_id") as fh:
        return fh.read().strip()


def load_blocked():
    # shortcut: les règles nftables disparaissent au redémarrage ; on oublie alors la liste. Les rendre permanentes = règles firewalld.
    try:
        with open(BLOCKED_FILE) as fh:
            data = json.load(fh)
        return set(data["ips"]) if data.get("boot") == boot_id() else set()
    except (OSError, ValueError, KeyError):
        return set()


def save_blocked(ips):
    tmp = BLOCKED_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump({"boot": boot_id(), "ips": sorted(ips)}, fh)
    os.replace(tmp, BLOCKED_FILE)


BLOCKED = load_blocked()

# --- Détection des menaces ---------------------------------------------------------------
# Listes publiques téléchargées entières (on n'envoie aucune de nos IP), rafraîchies une fois par jour.
FEEDS = {"feodo.txt": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "serveur de contrôle de virus connu (abuse.ch Feodo)"),
         "spamhaus-drop.txt": ("https://www.spamhaus.org/drop/drop.txt", "réseau criminel connu (Spamhaus DROP)")}
THREATS = []   # [(réseau, raison)]
SHELLS = {"bash", "sh", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "telnet", "busybox"}
INTERPRETERS = re.compile(r"^(python[\d.]*|perl|ruby|php[\d.]*|lua[\d.]*|tclsh|awk|gawk|pwsh)$")
BAD_PORTS = {"4444": "port par défaut de Metasploit", "4445": "port de reverse shell courant", "1337": "port « leet » de hacker",
             "31337": "port « eleet » de backdoor", "5555": "port de reverse shell courant", "6666": "port IRC (botnets)",
             "6667": "port IRC (botnets)", "6697": "port IRC (botnets)", "9001": "port Tor", "9050": "proxy Tor", "1234": "port de test de reverse shell"}
SAFE_PORTS = {"53", "67", "68", "80", "123", "443", "853", "5353"}
TMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")


def load_feeds():
    nets = []
    for name, (url, reason) in FEEDS.items():
        path = os.path.join(HERE, name)
        try:
            if not os.path.exists(path) or time.time() - os.path.getmtime(path) > 86400:
                with urllib.request.urlopen(url, timeout=20) as r, open(path + ".tmp", "wb") as fh:
                    fh.write(r.read())
                os.replace(path + ".tmp", path)
        except OSError:
            pass   # hors ligne : on garde l'ancienne copie s'il y en a une
        try:
            with open(path) as fh:
                for line in fh:
                    tok = line.split(";")[0].split("#")[0].strip()
                    if tok:
                        try:
                            nets.append((ipaddress.ip_network(tok, strict=False), reason))
                        except ValueError:
                            pass
        except OSError:
            pass
    THREATS[:] = nets


def feeds_loop():
    while True:
        load_feeds()
        time.sleep(86400)


def proc_info(pid, cache):
    """Ce qu'on peut lire de /proc pour un processus (seulement les nôtres sans droits root)."""
    if pid in cache:
        return cache[pid]
    info = {"exe": None, "socket_stdio": False}
    try:
        info["exe"] = os.readlink(f"/proc/{pid}/exe")
        info["socket_stdio"] = any(os.readlink(f"/proc/{pid}/fd/{fd}").startswith("socket:") for fd in (0, 1, 2))
    except OSError:
        pass
    cache[pid] = info
    return info


def assess(p, cache):
    """Niveau de menace d'une IP : danger (rouge), suspect (orange) ou normal, avec les raisons."""
    danger, suspect = [], []
    ip = ipaddress.ip_address(p["ip"])
    for net, reason in THREATS:
        if ip.version == net.version and ip in net:
            danger.append(reason)
            break
    for c in p["conns"]:
        port = c["lport"] if c["inbound"] else c["rport"]
        if port in BAD_PORTS:
            (danger if c["procs"] and any(u["name"] in SHELLS for u in c["procs"]) else suspect).append(f"port {port} : {BAD_PORTS[port]}")
        if not c["procs"] and p["country"] != "LAN" and port not in SAFE_PORTS:
            suspect.append(f"programme invisible (root ou autre utilisateur) sur le port {port}")
        for u in c["procs"]:
            info = proc_info(u["pid"], cache)
            exe = info["exe"] or ""
            if u["name"] in SHELLS or INTERPRETERS.match(u["name"]):
                if info["socket_stdio"]:
                    danger.append(f"REVERSE SHELL probable : {u['name']} (PID {u['pid']}) a son clavier/écran branché sur le réseau")
                elif u["name"] in SHELLS:
                    suspect.append(f"shell réseau : {u['name']} (PID {u['pid']}) connecté directement")
                elif p["country"] != "LAN":
                    suspect.append(f"interpréteur de script {u['name']} (PID {u['pid']}) connecté à l'extérieur")
            if exe.endswith(" (deleted)"):
                danger.append(f"{u['name']} (PID {u['pid']}) tourne depuis un fichier supprimé — technique courante des malwares")
            elif exe.startswith(TMP_DIRS):
                danger.append(f"{u['name']} (PID {u['pid']}) lancé depuis un dossier temporaire ({exe})")
    p["threat"] = "danger" if danger else "suspect" if suspect else "normal"
    p["reasons"] = list(dict.fromkeys(danger + suspect))


def split_addr(s):
    """'1.2.3.4:443' / '[::1]:443' / '1.2.3.4%wlan0:68' -> (ip, port)."""
    host, _, port = s.rpartition(":")
    return host.strip("[]").split("%")[0], port


def ss(*args):
    return subprocess.run(["ss", "-H", *args], capture_output=True, text=True, timeout=5).stdout.splitlines()


def listening_ports():
    ports = set()
    for line in ss("-tuln"):
        f = line.split()
        if len(f) >= 5:
            ports.add(split_addr(f[4])[1])
    return ports


def geo(ip):
    a = ipaddress.ip_address(ip)
    if not a.is_global:
        return {"country": "LAN", "country_name": "Réseau local", "city": "", "region": "", "lat": None, "lon": None, "asn": None, "org": "Réseau local"}
    r = CITY.get(ip) or {}
    s = ASN.get(ip) or {}
    names = r.get("country", {}).get("names", {})
    loc = r.get("location", {})
    subs = r.get("subdivisions") or [{}]
    return {"country": r.get("country", {}).get("iso_code", "??"),
            "country_name": names.get("fr") or names.get("en", "Inconnu"),
            "city": r.get("city", {}).get("names", {}).get("en", ""),
            "region": subs[0].get("names", {}).get("en", ""),
            "lat": loc.get("latitude"), "lon": loc.get("longitude"),
            "asn": s.get("autonomous_system_number"), "org": s.get("autonomous_system_organization", "Inconnu")}


def connections():
    listen = listening_ports()
    peers, last = {}, None
    for line in ss("-tunpi", "state", "established"):
        if line[:1].isspace():            # ligne de détails TCP de la connexion précédente
            if last is not None:
                last.update({k: float(v) for k, v in TCPINFO.findall(line)})
            continue
        f = line.split()
        if len(f) < 5:
            last = None
            continue
        proto, (lip, lport), (rip, rport) = f[0], split_addr(f[3]), split_addr(f[4])
        if ipaddress.ip_address(rip).is_loopback:
            last = None
            continue
        users = USERS.findall(" ".join(f[5:]))
        conn = {"proto": proto, "local": f"{lip}:{lport}", "rport": rport, "lport": lport,
                "inbound": lport in listen, "procs": [{"name": n, "pid": int(p)} for n, p in users],
                "recvq": int(f[1]), "sendq": int(f[2])}
        p = peers.setdefault(rip, {"ip": rip, "conns": []})
        p["conns"].append(conn)
        last = conn
    out, cache = [], {}
    for p in peers.values():
        p.update(geo(p["ip"]))
        assess(p, cache)
        cs = p["conns"]
        p["count"] = len(cs)
        p["procs"] = sorted({u["name"] for c in cs for u in c["procs"]})
        p["ports"] = sorted({c["rport"] for c in cs}, key=lambda x: int(x) if x.isdigit() else 0)
        p["protos"] = sorted({c["proto"] for c in cs})
        p["bytes_sent"] = sum(c.get("bytes_sent", 0) for c in cs)
        p["bytes_received"] = sum(c.get("bytes_received", 0) for c in cs)
        inbound = any(c["inbound"] for c in cs)
        p["direction"] = "local" if p["country"] == "LAN" else ("entrant" if inbound else "sortant")
        out.append(p)
    return out


def details(ip):
    """Infos plus lentes, demandées au clic : nom DNS inverse et détails des programmes."""
    try:
        rdns = POOL.submit(socket.gethostbyaddr, ip).result(timeout=2)[0]
    except Exception:
        rdns = None
    procs = {}
    for p in connections():
        if p["ip"] != ip:
            continue
        for c in p["conns"]:
            for u in c["procs"]:
                pid = u["pid"]
                if pid in procs:
                    continue
                info = {"name": u["name"], "pid": pid}
                try:
                    info["exe"] = os.readlink(f"/proc/{pid}/exe")
                    with open(f"/proc/{pid}/cmdline", "rb") as fh:
                        info["cmdline"] = fh.read().replace(b"\0", b" ").decode(errors="replace").strip()[:400]
                    info["user"] = __import__("pwd").getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
                except OSError:
                    pass
                procs[pid] = info
    return {"ip": ip, "rdns": rdns, "processes": list(procs.values())}


def checked_ip(raw):
    """Validation stricte : seule une IP publique ou locale réelle passe vers les commandes administrateur."""
    a = ipaddress.ip_address(raw)
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        raise ValueError("adresse refusée")
    return str(a)


def admin(*cmd):
    """Lance une commande système avec le mot de passe admin (fenêtre pkexec). Pas de shell : les arguments ne sont pas interprétés."""
    r = subprocess.run(["pkexec", *cmd], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip()
        raise RuntimeError("autorisation refusée" if r.returncode in (126, 127) else msg or f"code {r.returncode}")


def action(kind, raw_ip):
    ip = checked_ip(raw_ip)
    fam = "ip" if ipaddress.ip_address(ip).version == 4 else "ip6"
    sets = "add table inet ipglobe ; add set inet ipglobe b4 { type ipv4_addr ; } ; add set inet ipglobe b6 { type ipv6_addr ; } ; "
    if kind == "kill":                      # coupe les connexions ouvertes avec cette IP
        admin("/usr/bin/ss", "-K", "dst", ip)
    elif kind == "block":                   # bloque dans les deux sens, puis coupe ce qui est ouvert
        admin("/usr/bin/nft", sets +
              "add chain inet ipglobe out { type filter hook output priority -10 ; } ; "
              "add chain inet ipglobe in { type filter hook input priority -10 ; } ; "
              "flush chain inet ipglobe out ; flush chain inet ipglobe in ; "
              "add rule inet ipglobe out ip daddr @b4 reject ; add rule inet ipglobe out ip6 daddr @b6 reject ; "
              "add rule inet ipglobe in ip saddr @b4 drop ; add rule inet ipglobe in ip6 saddr @b6 drop ; "
              f"add element inet ipglobe {'b4' if fam == 'ip' else 'b6'} {{ {ip} }}")
        BLOCKED.add(ip)
        save_blocked(BLOCKED)
        subprocess.run(["ss", "-K", "dst", ip], capture_output=True, timeout=5)   # sans droits : coupe au moins nos propres sockets si le noyau l'accepte
    elif kind == "unblock":
        admin("/usr/bin/nft", sets + f"delete element inet ipglobe {'b4' if fam == 'ip' else 'b6'} {{ {ip} }}")
        BLOCKED.discard(ip)
        save_blocked(BLOCKED)
    else:
        raise ValueError("action inconnue")


# Bibliothèques de la page, téléchargées par install.sh et servies en local (pas de CDN : marche avec NoScript).
LIBS = {"three.min.js": "text/javascript", "3d-force-graph.min.js": "text/javascript",
        "topojson-client.min.js": "text/javascript", "countries-110m.json": "application/json"}


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Host") not in ALLOWED_HOSTS:
            return self.send_error(403)
        url = urlparse(self.path)
        if url.path == "/api/connections":
            return self.reply(200, {"host": socket.gethostname(), "peers": connections(), "blocked": sorted(BLOCKED)})
        if url.path == "/api/details":
            try:
                ip = str(ipaddress.ip_address(parse_qs(url.query).get("ip", [""])[0]))
            except ValueError:
                return self.reply(400, {"error": "IP invalide"})
            return self.reply(200, {**details(ip), **geo(ip)})
        lib = url.path.removeprefix("/lib/")
        if lib in LIBS:  # liste fermée : pas de lecture de fichier arbitraire
            with open(os.path.join(HERE, "lib", lib), "rb") as fh:
                return self.reply(200, fh.read(), LIBS[lib])
        if url.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as fh:
                return self.reply(200, fh.read().replace(b"__TOKEN__", TOKEN.encode()), "text/html; charset=utf-8")
        self.send_error(404)

    def do_POST(self):
        if self.headers.get("Host") not in ALLOWED_HOSTS or not secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN):
            return self.send_error(403)
        if urlparse(self.path).path != "/api/action":
            return self.send_error(404)
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)) or b"{}")
            action(body.get("action"), body.get("ip", ""))
            self.reply(200, {"ok": True, "blocked": sorted(BLOCKED)})
        except (ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
            self.reply(400, {"error": str(e) or "échec"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        assert split_addr("[2600:1901:0:9e23::]:443") == ("2600:1901:0:9e23::", "443")
        assert split_addr("192.168.1.4%wlan0:68") == ("192.168.1.4", "68")
        assert geo("192.168.1.254")["country"] == "LAN"
        assert geo("35.186.224.39")["org"] == "Google LLC"
        for bad in ("127.0.0.1", "0.0.0.0", "1.2.3.4; rm -rf /", "::1", "224.0.0.1", ""):
            try:
                checked_ip(bad)
                raise AssertionError(bad)
            except ValueError:
                pass
        assert checked_ip("8.8.8.8") == "8.8.8.8"
        cs = connections()
        assert all("conns" in p and p["count"] == len(p["conns"]) for p in cs)
        load_feeds()
        assert THREATS, "listes de menaces vides"
        bad = {"ip": str(THREATS[-1][0][1]), "country": "XX", "conns": []}
        assess(bad, {})
        assert bad["threat"] == "danger", bad
        # faux reverse shell : un bash dont l'entrée standard est une socket
        a, b = socket.socketpair()
        sh = subprocess.Popen(["bash", "-c", "sleep 5"], stdin=a)
        fake = {"ip": "8.8.8.8", "country": "US", "conns": [{"inbound": False, "lport": "5000", "rport": "4444", "procs": [{"name": "bash", "pid": sh.pid}]}]}
        assess(fake, {})
        sh.kill(); a.close(); b.close()
        assert fake["threat"] == "danger" and any("REVERSE SHELL" in r for r in fake["reasons"]), fake
        cs = connections()
        print("selftest OK,", len(THREATS), "réseaux malveillants chargés,", len(cs), "IP,",
              {lvl: sum(p["threat"] == lvl for p in cs) for lvl in ("danger", "suspect", "normal")})
        for p in cs:
            if p["reasons"]:
                print(" ", p["threat"], p["ip"], p["reasons"][:2])
        if cs:
            print(json.dumps(details(cs[0]["ip"]), ensure_ascii=False)[:300])
        sys.exit()
    threading.Thread(target=feeds_loop, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
