import requests, yaml, os, socket, time, base64, json, re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

SOURCES = [
    
    ("https://www.freeproxy.world/?type=http&anonymity=&country=IR", "html-http"),
    ("https://www.freeproxy.world/?type=socks5&anonymity=&country=IR", "html-socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http"),
    ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http"),
    ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "socks5"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt", "vmess"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt", "vless"),
    ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt", "ss"),
    ("https://raw.githubusercontent.com/iranxray/hope/main/singbox", "vless"),
    ("https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/singbox", "vless"),
    ("https://proxyhub.me/en/ir-http-proxy-list.html", "html-http"),
    ("https://proxyhub.me/en/ir-sock5-proxy-list.html", "html-socks5"),
    ("https://www.proxydocker.com/en/socks5-list/country/Iran", "html-socks5"),
    ("https://www.proxydocker.com/en/proxylist/search?need=all&type=http-https&anonymity=all&port=&country=Iran&city=&state=all", "html-http"),
    ("https://raw.githubusercontent.com/freefq/free/master/v2", "vmess"),
    ("https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", "mixed"),
    ("https://www.v2rayse.com/node/free", "html-mixed"),
]

failed_sources = []

def is_alive(ip, port, timeout=7):
    try:
        start = time.time()
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        ping = int((time.time() - start) * 1000)
        return True, ping
    except:
        return False, None

def ip_is_ir(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return r.get("countryCode") == "IR"
    except:
        return False

def parse_ss(url):
    try:
        url = url[5:]
        if "#" in url:
            url, tag = url.split("#", 1)
        else:
            tag = "ss"
        if "@" not in url:
            url = base64.b64decode(url + "==").decode()
            method, rest = url.split(":", 1)
            password, serverport = rest.split("@")
            server, port = serverport.split(":")
        else:
            userinfo, serverinfo = url.split("@")
            method, password = base64.b64decode(userinfo + "==").decode().split(":")
            server, port = serverinfo.split(":")
        return {
            "name": tag,
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True
        }
    except:
        return None

def parse_vless(url):
    try:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        return {
            "name": parsed.fragment or f"{parsed.hostname}:{parsed.port}",
            "type": "vless",
            "server": parsed.hostname,
            "port": int(parsed.port),
            "uuid": parsed.username,
            "tls": q.get("security", ["none"])[0] == "tls",
            "udp": True,
            "network": q.get("type", ["tcp"])[0],
            "ws-opts": {
                "path": q.get("path", ["/"])[0],
                "headers": {"Host": q.get("host", [""])[0]}
            } if q.get("type", ["tcp"])[0] == "ws" else {}
        }
    except:
        return None

def fetch_html_proxies(url, proxy_type):
    proxies = []
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(url, headers=headers, timeout=15)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")

        if "freeproxy.world" in url:
            table = soup.find("table")
            rows = table.find_all("tr")[1:] if table else []
            for row in rows:
                cols = row.find_all("td")
                if len(cols) < 2:
                    continue
                ip = cols[0].get_text(strip=True)
                port = cols[1].get_text(strip=True)
                proxies.append((ip, port, "socks5" if "socks5" in proxy_type else "http"))
        else:
            rows = soup.find_all("tr")
            for row in rows:
                cols = row.find_all("td")
                if len(cols) < 2:
                    continue
                ip, port = cols[0].text.strip(), cols[1].text.strip()
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    continue
                proxies.append((ip, port, "socks5" if "socks5" in proxy_type else "http"))

        return proxies
    except Exception as e:
        print(f"⚠️ Failed to fetch from {url}: {e}")
        failed_sources.append(url)
        return []

proxies_all = []
proxy_names_clean = []
proxy_names_all = []
seen_ips = set()

for url, ptype in SOURCES:
    print(f"🔍 بررسی منبع: {url}")
    if ptype.startswith("html-"):
        extracted = fetch_html_proxies(url, ptype)
        print(f"📄 {len(extracted)} پراکسی از HTML استخراج شد")
        for ip, port, proto in extracted:
            if ip in seen_ips or not ip_is_ir(ip):
                continue
            seen_ips.add(ip)
            alive, ping = is_alive(ip, port)
            name = f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}"
            proxy = {
                "name": name,
                "type": proto,
                "server": ip,
                "port": int(port),
                "udp": True
            }
            proxies_all.append(proxy)
            proxy_names_all.append(name)
            if alive: proxy_names_clean.append(name)
        continue

    try:
        r = requests.get(url, timeout=20)
        lines = r.text.strip().splitlines()
    except Exception as e:
        print(f"⚠️ خطا در {url}: {e}")
        failed_sources.append(url)
        continue

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            if ptype == "vmess" and line.startswith("vmess://"):
                decoded = base64.b64decode(line[8:] + "==").decode()
                conf = json.loads(decoded)
                ip = conf.get("add")
                port = conf.get("port")
                if not ip or not port or not ip_is_ir(ip): continue
                alive, ping = is_alive(ip, port)
                name = f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}"
                proxy = {
                    "name": name,
                    "type": "vmess",
                    "server": ip,
                    "port": int(port),
                    "uuid": conf.get("id"),
                    "alterId": int(conf.get("aid", 0)),
                    "cipher": conf.get("cipher", "auto"),
                    "tls": conf.get("tls") == "tls",
                    "network": conf.get("net", "tcp"),
                    "udp": True
                }
                if conf.get("net") == "ws":
                    proxy["ws-opts"] = {
                        "path": conf.get("path", "/"),
                        "headers": {"Host": conf.get("host", "")}
                    }
                proxies_all.append(proxy)
                proxy_names_all.append(name)
                if alive: proxy_names_clean.append(name)
            elif ptype == "vless" and line.startswith("vless://"):
                conf = parse_vless(line)
                if not conf or not ip_is_ir(conf["server"]): continue
                alive, ping = is_alive(conf["server"], conf["port"])
                conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
                proxies_all.append(conf)
                proxy_names_all.append(conf["name"])
                if alive: proxy_names_clean.append(conf["name"])
            elif ptype == "ss" and line.startswith("ss://"):
                conf = parse_ss(line)
                if not conf or not ip_is_ir(conf["server"]): continue
                alive, ping = is_alive(conf["server"], conf["port"])
                conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
                proxies_all.append(conf)
                proxy_names_all.append(conf["name"])
                if alive: proxy_names_clean.append(conf["name"])
            elif ":" in line and ptype in ["http", "socks5"]:
                ip, port = line.split(":")[:2]
                if ip in seen_ips or not ip_is_ir(ip): continue
                seen_ips.add(ip)
                alive, ping = is_alive(ip, port)
                name = f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}"
                proxy = {
                    "name": name,
                    "type": ptype,
                    "server": ip,
                    "port": int(port),
                    "udp": True
                }
                proxies_all.append(proxy)
                proxy_names_all.append(name)
                if alive: proxy_names_clean.append(name)
        except:
            continue

if not proxy_names_all:
    proxy_names_all.append("DIRECT")
if not proxy_names_clean:
    proxy_names_clean.append("DIRECT")

config = {
    "mixed-port": 7890,
    "allow-lan": True,
    "interface-name": "utun",
    "mode": "Rule",
    "log-level": "info",
    "tun": {
        "enable": True,
        "stack": "system",
        "dns-hijack": ["any:53"]
    },
    "proxies": proxies_all,
    "proxy-groups": [
        {"name": "MAIN", "type": "select", "proxies": ["IR-AUTO", "IR-BALANCE", "IR-ALL", "IR-ALL-RAW"]},
        {"name": "IR-ALL", "type": "select", "proxies": proxy_names_clean},
        {"name": "IR-ALL-RAW", "type": "select", "proxies": proxy_names_all},
        {"name": "IR-AUTO", "type": "fallback", "proxies": proxy_names_all, "url": "https://google.com", "interval": 600, "timeout": 60000},
        {"name": "IR-BALANCE", "type": "load-balance", "strategy": "round-robin", "proxies": proxy_names_all, "url": "https://google.com", "interval": 600, "timeout": 60000}
    ],
    "rules": ["MATCH,MAIN"]
}

os.makedirs("output", exist_ok=True)
with open("output/config.yaml", "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True)

print(f"✅ Done: {len(proxy_names_all)} total — {len(proxy_names_clean)} valid.")
if failed_sources:
    print("❌ منابع شکست‌خورده:")
    for s in failed_sources:
        print(" -", s)
