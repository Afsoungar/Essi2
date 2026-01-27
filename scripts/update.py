#!/usr/bin/env python3
"""
اسکریپت مدیریت پروکسی‌های ایرانی
ویژگی‌ها:
- دریافت پروکسی‌های جدید از منابع مختلف (همه پروتکل‌ها)
- حذف تکراری‌ها
- مدیریت پروکسی‌های قدیمی بر اساس دو شرط همزمان
- حفظ حداقل 50 پروکسی فعال
"""

import yaml
import requests
from datetime import datetime, timedelta
import os
import sys
import socket
import time
import base64
import json
import re
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Tuple, Set

class IranProxyManager:
    def __init__(self, config_path: str = "output/config.yaml"):
        """
        مقداردهی اولیه مدیر پروکسی
        """
        self.config_path = config_path
        self.config = self.load_config()
        self.failed_sources = []
        
        # منابع ایرانی (همان ریپوی قبلی + منابع جدید)
        self.SOURCES = [
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
            ("https://proxyhub.me/en/ir-http-proxy-list.html", "html-http"),
            ("https://proxyhub.me/en/ir-sock5-proxy-list.html", "html-socks5"),
            ("https://www.proxydocker.com/en/socks5-list/country/Iran", "html-socks5"),
            ("https://www.proxydocker.com/en/proxylist/search?need=all&type=http-https&anonymity=all&port=&country=Iran&city=&state=all", "html-http"),
            # منابع جدید ایرانی
            ("https://raw.githubusercontent.com/iranxray/hope/main/singbox", "vless"),
            ("https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/singbox", "vless"),
            ("https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sb", "ss"),
            ("https://raw.githubusercontent.com/freefq/free/master/v2", "vmess"),
            ("https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", "mixed"),
            ("https://raw.githubusercontent.com/BlueSkyXN/9.DDFHP/main/1", "mixed"),
        ]
    
    def load_config(self) -> Dict[str, Any]:
        """بارگذاری فایل کانفیگ"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {"proxies": [], "metadata": {}}
                    print(f"📂 فایل کانفیگ با {len(config.get('proxies', []))} پروکسی بارگذاری شد")
                    return config
            else:
                print("📂 فایل کانفیگ یافت نشد. ایجاد فایل جدید...")
                return {"proxies": [], "metadata": {}}
        except Exception as e:
            print(f"❌ خطا در بارگذاری کانفیگ: {e}")
            return {"proxies": [], "metadata": {}}
    
    def save_config(self):
        """ذخیره فایل کانفیگ"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            # به‌روزرسانی metadata
            self.config['metadata'] = {
                'total_count': len(self.config.get('proxies', [])),
                'last_updated': datetime.utcnow().isoformat(),
                'retention_days': 3,
                'min_proxies': 50,
                'sources_used': len(self.SOURCES)
            }
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, 
                         allow_unicode=True, sort_keys=False, width=120)
            
            print(f"💾 فایل کانفیگ ذخیره شد ({len(self.config.get('proxies', []))} پروکسی)")
            return True
        except Exception as e:
            print(f"❌ خطا در ذخیره کانفیگ: {e}")
            return False
    
    def is_alive(self, ip: str, port: int, timeout: int = 7) -> Tuple[bool, int]:
        """بررسی فعال بودن پروکسی"""
        try:
            start = time.time()
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            ping = int((time.time() - start) * 1000)
            return True, ping
        except:
            return False, 0
    
    def ip_is_ir(self, ip: str) -> bool:
        """بررسی ایرانی بودن IP"""
        try:
            # ابتدا از API رایگان استفاده می‌کنیم
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                return data.get("countryCode") == "IR"
        except:
            pass
        
        # اگر API کار نکرد، از رنج‌های IP ایرانی استفاده می‌کنیم
        iran_ranges = [
            '5.', '31.', '37.', '46.', '62.', '77.', '78.', '79.', 
            '85.', '86.', '87.', '89.', '91.', '92.', '93.', '94.', 
            '95.', '98.', '185.', '188.', '212.'
        ]
        return any(ip.startswith(prefix) for prefix in iran_ranges)
    
    def normalize_proxy_address(self, proxy_address: str) -> str:
        """نرمال‌سازی آدرس پروکسی"""
        if not proxy_address:
            return ""
        
        proxy_address = proxy_address.strip()
        
        # حذف پروتکل‌ها
        for protocol in ['http://', 'https://', 'socks4://', 'socks5://', 'socks://']:
            if proxy_address.lower().startswith(protocol):
                proxy_address = proxy_address[len(protocol):]
        
        # تقسیم به IP و پورت
        parts = proxy_address.split(':')
        if len(parts) == 2:
            ip, port = parts
            ip = ip.strip()
            port = port.strip()
            return f"{ip}:{port}".lower()
        
        return proxy_address.lower()
    
    def parse_ss(self, url: str) -> Dict[str, Any]:
        """پارس کردن لینک Shadowsocks"""
        try:
            url = url[5:]  # حذف ss://
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
    
    def parse_vless(self, url: str) -> Dict[str, Any]:
        """پارس کردن لینک VLESS"""
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
    
    def fetch_html_proxies(self, url: str, proxy_type: str) -> List[Tuple[str, str, str]]:
        """استخراج پروکسی از صفحات HTML"""
        proxies = []
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
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
            print(f"⚠️ خطا در دریافت از {url}: {e}")
            self.failed_sources.append(url)
            return []
    
    def fetch_all_proxies(self) -> List[Dict[str, Any]]:
        """دریافت همه پروکسی‌ها از منابع"""
        proxies_all = []
        seen_keys = set()  # برای جلوگیری از تکراری‌ها
        
        print(f"\n📥 دریافت پروکسی‌ها از {len(self.SOURCES)} منبع:")
        print("-" * 50)
        
        for url, ptype in self.SOURCES:
            try:
                print(f"🔍 منبع: {url[:60]}...")
                
                if ptype.startswith("html-"):
                    extracted = self.fetch_html_proxies(url, ptype)
                    print(f"   📄 {len(extracted)} پروکسی از HTML استخراج شد")
                    
                    for ip, port, proto in extracted:
                        if ip in [p.get('server') for p in proxies_all if p.get('type') == proto]:
                            continue
                        
                        if not self.ip_is_ir(ip):
                            continue
                        
                        alive, ping = self.is_alive(ip, int(port))
                        
                        proxy_data = {
                            "name": f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}",
                            "type": proto,
                            "server": ip,
                            "port": int(port),
                            "added_date": datetime.now().strftime('%Y-%m-%d'),
                            "last_checked": datetime.now().strftime('%Y-%m-%d'),
                            "is_active": alive,
                            "country": "IR",
                            "ping": ping if alive else 0,
                            "source": url
                        }
                        proxies_all.append(proxy_data)
                    continue

                # دریافت از منابع متنی/API
                response = requests.get(url, timeout=20, 
                                      headers={"User-Agent": "Mozilla/5.0"})
                
                if response.status_code != 200:
                    print(f"   ❌ خطا HTTP {response.status_code}")
                    self.failed_sources.append(url)
                    continue
                
                lines = response.text.strip().splitlines()
                added_from_source = 0
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        # پردازش VMESS
                        if ptype == "vmess" and line.startswith("vmess://"):
                            decoded = base64.b64decode(line[8:] + "==").decode()
                            conf = json.loads(decoded)
                            ip = conf.get("add")
                            port = conf.get("port")
                            
                            if not ip or not port or not self.ip_is_ir(ip):
                                continue
                            
                            key = f"{ip}:{port}-vmess"
                            if key in seen_keys:
                                continue
                            seen_keys.add(key)
                            
                            alive, ping = self.is_alive(ip, port)
                            proxy_data = {
                                "name": f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}",
                                "type": "vmess",
                                "server": ip,
                                "port": int(port),
                                "uuid": conf.get("id"),
                                "alterId": int(conf.get("aid", 0)),
                                "cipher": conf.get("cipher", "auto"),
                                "tls": conf.get("tls") == "tls",
                                "network": conf.get("net", "tcp"),
                                "added_date": datetime.now().strftime('%Y-%m-%d'),
                                "last_checked": datetime.now().strftime('%Y-%m-%d'),
                                "is_active": alive,
                                "country": "IR",
                                "ping": ping if alive else 0,
                                "source": url
                            }
                            
                            if conf.get("net") == "ws":
                                proxy_data["ws-opts"] = {
                                    "path": conf.get("path", "/"),
                                    "headers": {"Host": conf.get("host", "")}
                                }
                            
                            proxies_all.append(proxy_data)
                            added_from_source += 1
                        
                        # پردازش VLESS
                        elif ptype == "vless" and line.startswith("vless://"):
                            conf = self.parse_vless(line)
                            if not conf or not self.ip_is_ir(conf["server"]):
                                continue
                            
                            key = f"{conf['server']}:{conf['port']}-vless"
                            if key in seen_keys:
                                continue
                            seen_keys.add(key)
                            
                            alive, ping = self.is_alive(conf["server"], conf["port"])
                            conf["added_date"] = datetime.now().strftime('%Y-%m-%d')
                            conf["last_checked"] = datetime.now().strftime('%Y-%m-%d')
                            conf["is_active"] = alive
                            conf["country"] = "IR"
                            conf["ping"] = ping if alive else 0
                            conf["source"] = url
                            conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
                            
                            proxies_all.append(conf)
                            added_from_source += 1
                        
                        # پردازش Shadowsocks
                        elif ptype == "ss" and line.startswith("ss://"):
                            conf = self.parse_ss(line)
                            if not conf or not self.ip_is_ir(conf["server"]):
                                continue
                            
                            key = f"{conf['server']}:{conf['port']}-ss"
                            if key in seen_keys:
                                continue
                            seen_keys.add(key)
                            
                            alive, ping = self.is_alive(conf["server"], conf["port"])
                            conf["added_date"] = datetime.now().strftime('%Y-%m-%d')
                            conf["last_checked"] = datetime.now().strftime('%Y-%m-%d')
                            conf["is_active"] = alive
                            conf["country"] = "IR"
                            conf["ping"] = ping if alive else 0
                            conf["source"] = url
                            conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
                            
                            proxies_all.append(conf)
                            added_from_source += 1
                        
                        # پردازش HTTP/SOCKS5
                        elif ":" in line and ptype in ["http", "socks5", "mixed"]:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                ip = parts[0].strip()
                                port = parts[1].strip()
                                
                                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                                    continue
                                
                                proto = ptype
                                if proto == "mixed":
                                    proto = "http" if len(parts) == 2 else "socks5"
                                
                                key = f"{ip}:{port}-{proto}"
                                if key in seen_keys:
                                    continue
                                seen_keys.add(key)
                                
                                if not self.ip_is_ir(ip):
                                    continue
                                
                                alive, ping = self.is_alive(ip, int(port))
                                
                                proxy_data = {
                                    "name": f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}",
                                    "type": proto,
                                    "server": ip,
                                    "port": int(port),
                                    "added_date": datetime.now().strftime('%Y-%m-%d'),
                                    "last_checked": datetime.now().strftime('%Y-%m-%d'),
                                    "is_active": alive,
                                    "country": "IR",
                                    "ping": ping if alive else 0,
                                    "source": url
                                }
                                proxies_all.append(proxy_data)
                                added_from_source += 1
                    
                    except Exception as e:
                        continue
                
                if added_from_source > 0:
                    print(f"   ✅ {added_from_source} پروکسی جدید")
                else:
                    print(f"   ℹ️  هیچ پروکسی جدیدی")
            
            except Exception as e:
                print(f"   ⚠️  خطا: {str(e)[:40]}")
                self.failed_sources.append(url)
        
        print("-" * 50)
        print(f"📊 مجموع {len(proxies_all)} پروکسی دریافت شد")
        return proxies_all
    
    def add_new_proxies(self, new_proxies: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        اضافه کردن پروکسی‌های جدید به لیست موجود
        
        Returns:
            (تعداد اضافه شده, تعداد تکراری)
        """
        existing_keys = set()
        for proxy in self.config.get('proxies', []):
            key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}-{proxy.get('type', '')}"
            existing_keys.add(key)
        
        added_count = 0
        duplicate_count = 0
        
        for proxy in new_proxies:
            key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}-{proxy.get('type', '')}"
            if key not in existing_keys:
                self.config.setdefault('proxies', []).append(proxy)
                added_count += 1
            else:
                duplicate_count += 1
        
        return added_count, duplicate_count
    
    def should_remove_old_proxies(self) -> Tuple[bool, List[Dict], int]:
        """
        بررسی شرایط حذف پروکسی‌های قدیمی
        
        شرط ۱: تعداد کل پروکسی‌ها > ۵۰
        شرط ۲: پروکسی‌های قدیمی‌تر از ۳ روز وجود داشته باشند
        """
        total_proxies = len(self.config.get('proxies', []))
        
        # شرط ۱: تعداد کل باید بیشتر از ۵۰ باشد
        if total_proxies <= 50:
            return False, [], 0
        
        # محاسبه تعداد اضافی
        excess_count = total_proxies - 50
        
        # شرط ۲: یافتن پروکسی‌های قدیمی‌تر از ۳ روز
        today = datetime.now()
        cutoff_date = today - timedelta(days=3)
        
        old_proxies = []
        for proxy in self.config.get('proxies', []):
            try:
                added_date = datetime.strptime(proxy['added_date'], '%Y-%m-%d')
                if added_date < cutoff_date:
                    old_proxies.append(proxy)
            except (ValueError, KeyError):
                continue
        
        # مرتب‌سازی بر اساس تاریخ (قدیمی‌ترین اول)
        old_proxies.sort(key=lambda x: datetime.strptime(x['added_date'], '%Y-%m-%d'))
        
        # بررسی آیا هر دو شرط برقرارند
        should_remove = len(old_proxies) > 0 and excess_count > 0
        
        return should_remove, old_proxies, excess_count
    
    def remove_old_proxies_with_conditions(self) -> int:
        """
        حذف پروکسی‌های قدیمی در صورت برقراری شرایط
        """
        should_remove, old_proxies, excess_count = self.should_remove_old_proxies()
        
        if not should_remove:
            return 0
        
        # ایجاد مجموعه از کلیدهای پروکسی‌های قدیمی برای حذف سریع‌تر
        old_keys_to_remove = set()
        for proxy in old_proxies[:excess_count]:  # فقط به تعداد اضافی
            key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}-{proxy.get('type', '')}"
            old_keys_to_remove.add(key)
        
        # فیلتر کردن لیست پروکسی‌ها
        remaining_proxies = []
        removed_count = 0
        
        for proxy in self.config.get('proxies', []):
            key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}-{proxy.get('type', '')}"
            
            # اگر پروکسی در لیست حذف بود و هنوز نیاز به حذف داریم
            if key in old_keys_to_remove and removed_count < excess_count:
                removed_count += 1
                continue  # حذف این پروکسی
            
            remaining_proxies.append(proxy)
        
        # به‌روزرسانی لیست
        self.config['proxies'] = remaining_proxies
        
        return removed_count
    
    def ensure_minimum_proxies(self):
        """اطمینان از وجود حداقل ۵۰ پروکسی فعال"""
        active_proxies = [p for p in self.config.get('proxies', []) if p.get('is_active', False)]
        
        if len(active_proxies) >= 50:
            print(f"✅ {len(active_proxies)} پروکسی فعال موجود است (کافی است)")
            return
        
        needed = 50 - len(active_proxies)
        print(f"⚠️  فقط {len(active_proxies)} پروکسی فعال داریم. نیاز به {needed} پروکسی بیشتر")
        
        # منابع اضافی برای مواقع اضطراری
        emergency_sources = [
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all", "http"),
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all", "socks5"),
            ("https://www.proxyscan.io/download?type=http", "http"),
        ]
        
        print("🔍 تلاش برای دریافت پروکسی‌های بیشتر از منابع اضافی...")
        
        # اضافه کردن منابع اضطراری موقتاً
        original_sources = self.SOURCES.copy()
        self.SOURCES.extend(emergency_sources)
        
        # دریافت پروکسی‌های بیشتر
        new_emergency_proxies = self.fetch_all_proxies()
        added, _ = self.add_new_proxies(new_emergency_proxies)
        
        # بازگرداندن منابع اصلی
        self.SOURCES = original_sources
        
        if added > 0:
            print(f"✅ {added} پروکسی اضطراری اضافه شد")
        else:
            print("❌ نتوانستیم پروکسی اضطراری اضافه کنیم")
    
    def create_clash_config(self):
        """ایجاد کانفیگ Clash نهایی"""
        proxy_names_all = []
        proxy_names_clean = []
        
        for proxy in self.config.get('proxies', []):
            name = proxy.get('name', f"{proxy.get('server')}:{proxy.get('port')}")
            if name:
                proxy_names_all.append(name)
                if proxy.get('is_active', False):
                    proxy_names_clean.append(name)
        
        # اگر هیچ پروکسی نداریم، DIRECT اضافه کن
        if not proxy_names_all:
            proxy_names_all.append("DIRECT")
            proxy_names_clean.append("DIRECT")
        
        clash_config = {
            "mixed-port": 7890,
            "allow-lan": True,
            "mode": "Rule",
            "log-level": "info",
            "proxies": self.config.get('proxies', []),
            "proxy-groups": [
                {
                    "name": "MAIN", 
                    "type": "select", 
                    "proxies": ["IR-AUTO", "IR-BALANCE", "IR-ALL", "IR-ALL-RAW"]
                },
                {
                    "name": "IR-ALL", 
                    "type": "select", 
                    "proxies": proxy_names_clean
                },
                {
                    "name": "IR-ALL-RAW", 
                    "type": "select", 
                    "proxies": proxy_names_all
                },
                {
                    "name": "IR-AUTO", 
                    "type": "fallback", 
                    "proxies": proxy_names_all, 
                    "url": "http://www.gstatic.com/generate_204", 
                    "interval": 300,
                    "tolerance": 50
                },
                {
                    "name": "IR-BALANCE", 
                    "type": "load-balance", 
                    "strategy": "round-robin", 
                    "proxies": proxy_names_all, 
                    "url": "http://www.gstatic.com/generate_204", 
                    "interval": 300
                }
            ],
            "rules": [
                "MATCH,MAIN"
            ]
        }
        
        return clash_config
    
    def analyze_proxies(self):
        """تحلیل و ارائه آمار پروکسی‌ها"""
        proxies = self.config.get('proxies', [])
        today = datetime.now()
        
        # آمار سن پروکسی‌ها
        age_stats = {
            'today': 0,      # 0 روز
            '1_day': 0,      # 1 روز
            '2_days': 0,     # 2 روز
            '3_days': 0,     # 3 روز
            'older': 0       # بیشتر از 3 روز
        }
        
        # آمار نوع پروتکل
        protocol_stats = {}
        
        # آمار کشورها
        country_stats = {}
        
        # محاسبه آمار
        for proxy in proxies:
            # آمار سن
            try:
                added_date = datetime.strptime(proxy['added_date'], '%Y-%m-%d')
                age_days = (today - added_date).days
                
                if age_days == 0:
                    age_stats['today'] += 1
                elif age_days == 1:
                    age_stats['1_day'] += 1
                elif age_days == 2:
                    age_stats['2_days'] += 1
                elif age_days == 3:
                    age_stats['3_days'] += 1
                else:
                    age_stats['older'] += 1
            except:
                age_stats['older'] += 1
            
            # آمار پروتکل
            protocol = proxy.get('type', 'unknown')
            protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
            
            # آمار کشور
            country = proxy.get('country', 'UNKNOWN')
            country_stats[country] = country_stats.get(country, 0) + 1
        
        return {
            'total': len(proxies),
            'active': len([p for p in proxies if p.get('is_active', False)]),
            'age_stats': age_stats,
            'protocol_stats': protocol_stats,
            'country_stats': country_stats
        }
    
    def run(self) -> bool:
        """اجرای اصلی"""
        print("=" * 70)
        print("🚀 شروع فرآیند به‌روزرسانی پروکسی‌های ایرانی")
        print("=" * 70)
        
        try:
            # 1. وضعیت اولیه
            initial_count = len(self.config.get('proxies', []))
            initial_active = len([p for p in self.config.get('proxies', []) 
                                 if p.get('is_active', False)])
            print(f"📊 وضعیت اولیه:")
            print(f"   • تعداد کل پروکسی‌ها: {initial_count}")
            print(f"   • پروکسی‌های فعال: {initial_active}")
            print(f"   • حداقل مورد نیاز: 50")
            
            # 2. دریافت پروکسی‌های جدید
            new_proxies = self.fetch_all_proxies()
            print(f"\n📥 {len(new_proxies)} پروکسی جدید دریافت شد")
            
            # 3. اضافه کردن پروکسی‌های جدید
            added_count, duplicate_count = self.add_new_proxies(new_proxies)
            print(f"\n➕ اضافه کردن پروکسی‌های جدید:")
            print(f"   ✅ {added_count} پروکسی جدید اضافه شد")
            if duplicate_count > 0:
                print(f"   ⚠️  {duplicate_count} پروکسی تکراری نادیده گرفته شد")
            
            # 4. بررسی شرایط حذف
            print(f"\n🗑️  بررسی شرایط حذف پروکسی‌های قدیمی:")
            total_after_add = len(self.config.get('proxies', []))
            print(f"   تعداد پروکسی‌ها بعد از اضافه کردن: {total_after_add}")
            
            should_remove, old_proxies, excess_count = self.should_remove_old_proxies()
            
            if should_remove:
                print(f"   ✓ شرط ۱: تعداد پروکسی‌ها ({total_after_add}) > ۵۰")
                print(f"   ✓ شرط ۲: {len(old_proxies)} پروکسی قدیمی‌تر از ۳ روز")
                print(f"   ⚡ هر دو شرط برقرار است → حذف قدیمی‌ها")
                
                removed_count = self.remove_old_proxies_with_conditions()
                if removed_count > 0:
                    print(f"   ✅ {removed_count} پروکسی قدیمی حذف شدند")
                else:
                    print(f"   ℹ️  با وجود شرایط، پروکسی‌ای حذف نشد")
            else:
                print(f"   ⏸️  شرایط حذف برقرار نیست:")
                if total_after_add <= 50:
                    print(f"     ✗ تعداد کل ({total_after_add}) ≤ ۵۰")
                if len(old_proxies) == 0:
                    print(f"     ✗ پروکسی قدیمی‌تر از ۳ روز وجود ندارد")
            
            # 5. بررسی حداقل تعداد
            print(f"\n📊 بررسی حداقل تعداد پروکسی...")
            self.ensure_minimum_proxies()
            
            # 6. ایجاد کانفیگ Clash
            print(f"\n⚙️  ایجاد کانفیگ Clash...")
            clash_config = self.create_clash_config()
            self.config.update(clash_config)
            
            # 7. ذخیره فایل
            print(f"\n💾 ذخیره تغییرات...")
            if not self.save_config():
                return False
            
            # 8. گزارش نهایی
            final_count = len(self.config.get('proxies', []))
            final_active = len([p for p in self.config.get('proxies', []) 
                               if p.get('is_active', False)])
            analysis = self.analyze_proxies()
            
            print(f"\n" + "=" * 70)
            print("📈 گزارش نهایی")
            print("=" * 70)
            
            print(f"\n📊 آمار پروکسی‌ها:")
            print(f"   • مجموع: {analysis['total']}")
            print(f"   • فعال: {analysis['active']}")
            
            print(f"\n📅 توزیع سن:")
            print(f"   • امروزی: {analysis['age_stats']['today']}")
            print(f"   • ۱ روزه: {analysis['age_stats']['1_day']}")
            print(f"   • ۲ روزه: {analysis['age_stats']['2_days']}")
            print(f"   • ۳ روزه: {analysis['age_stats']['3_days']}")
            print(f"   • قدیمی: {analysis['age_stats']['older']}")
            
            print(f"\n🔌 توزیع پروتکل:")
            for protocol, count in analysis['protocol_stats'].items():
                print(f"   • {protocol}: {count}")
            
            print(f"\n🌍 توزیع کشورها:")
            for country, count in analysis['country_stats'].items():
                print(f"   • {country}: {count}")
            
            print(f"\n📈 تغییرات کلی: {final_count - initial_count:+d} پروکسی")
            print(f"📈 تغییرات فعال: {final_active - initial_active:+d} پروکسی")
            
            if final_active >= 50:
                print(f"\n✅ موفقیت: {final_active} پروکسی فعال موجود است")
            else:
                print(f"\n⚠️  هشدار: فقط {final_active} پروکسی فعال موجود است")
            
            if self.failed_sources:
                print(f"\n❌ منابع شکست‌خورده ({len(self.failed_sources)}):")
                for s in self.failed_sources[:3]:
                    print(f"   - {s}")
                if len(self.failed_sources) > 3:
                    print(f"   - و {len(self.failed_sources) - 3} منبع دیگر")
            
            print("\n" + "=" * 70)
            return True
            
        except KeyboardInterrupt:
            print("\n\n⏹️  عملیات توسط کاربر متوقف شد")
            return False
        except Exception as e:
            print(f"\n❌ خطای غیرمنتظره: {e}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """تابع اصلی"""
    print("🔧 مدیر پروکسی‌های ایرانی - نسخه پیشرفته")
    print("📅 " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print("⚡ همه پروتکل‌ها: HTTP, SOCKS5, VMESS, VLESS, Shadowsocks")
    
    manager = IranProxyManager()
    success = manager.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
