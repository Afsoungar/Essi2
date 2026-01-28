#!/usr/bin/env python3
"""
اسکریپت مدیریت پروکسی‌های ایرانی
بررسی مستقیم IP از سرویس‌های آنلاین با سیستم fallback
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
import random
import threading
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Tuple, Set, Optional

class Logger:
    """سیستم لاگ‌گیری پیشرفته با مدیریت خودکار فضای دیسک"""
    def __init__(self, log_dir="output/logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        
        # آمارها
        self.stats = {
            'total_proxies_received': 0,
            'iranian_proxies': 0,
            'non_iranian_proxies': 0,
            'active_proxies_found': 0,
            'inactive_proxies': 0,
            'duplicates_found': 0,
            'proxies_added': 0,
            'proxies_removed': 0,
            'ip_checks': 0,
            'ip_cache_hits': 0,
            'api_requests': 0,
            'api_failures': 0,
            'sources_used': 0,
            'sources_failed': 0,
            'old_logs_deleted': 0
        }
        
        # حذف لاگ‌های قدیمی‌تر از 2 هفته
        self.clean_old_logs()
        
        # فایل لاگ با timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(self.log_dir, f"proxy_update_{timestamp}.log")
        self.console_log_file = os.path.join(self.log_dir, "latest.log")
        
        # باز کردن فایل‌ها
        self.log_fd = open(self.log_file, 'w', encoding='utf-8')
        self.console_log_fd = open(self.console_log_file, 'w', encoding='utf-8')
    
    def clean_old_logs(self):
        """حذف لاگ‌های قدیمی‌تر از 2 هفته"""
        cutoff_date = datetime.now() - timedelta(days=14)
        deleted_count = 0
        
        if os.path.exists(self.log_dir):
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log'):
                    file_path = os.path.join(self.log_dir, filename)
                    
                    try:
                        if filename.startswith('proxy_update_'):
                            date_str = filename[13:21]  # YYYYMMDD
                            file_date = datetime.strptime(date_str, "%Y%m%d")
                            
                            if file_date < cutoff_date:
                                os.remove(file_path)
                                deleted_count += 1
                    except:
                        file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if file_mtime < cutoff_date:
                            os.remove(file_path)
                            deleted_count += 1
        
        self.stats['old_logs_deleted'] = deleted_count
        if deleted_count > 0:
            print(f"🗑️  حذف {deleted_count} فایل لاگ قدیمی (بیشتر از 2 هفته)")
    
    def log(self, message: str, level: str = "INFO"):
        """ذخیره لاگ در فایل و نمایش در کنسول"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        # چاپ در کنسول
        print(formatted_message)
        
        # ذخیره در فایل‌ها
        self.log_fd.write(formatted_message + "\n")
        self.console_log_fd.write(formatted_message + "\n")
        
        # flush برای اطمینان از ذخیره
        self.log_fd.flush()
        self.console_log_fd.flush()
    
    def update_stat(self, stat_name: str, value: int = 1):
        """به‌روزرسانی آمار"""
        if stat_name in self.stats:
            self.stats[stat_name] += value
    
    def print_stats(self):
        """چاپ آمار کامل"""
        self.log("\n" + "="*80, "STATS")
        self.log("📊 آمار کامل فرآیند به‌روزرسانی پروکسی", "STATS")
        self.log("="*80, "STATS")
        
        self.log(f"📥 دریافت از منابع:", "STATS")
        self.log(f"   • منابع استفاده شده: {self.stats['sources_used']}", "STATS")
        self.log(f"   • منابع شکست خورده: {self.stats['sources_failed']}", "STATS")
        self.log(f"   • کل پروکسی‌های دریافتی: {self.stats['total_proxies_received']:,}", "STATS")
        self.log(f"   • پروکسی‌های ایرانی شناسایی شده: {self.stats['iranian_proxies']:,}", "STATS")
        self.log(f"   • پروکسی‌های غیرایرانی حذف شده: {self.stats['non_iranian_proxies']:,}", "STATS")
        
        self.log(f"\n🔍 بررسی سلامت:", "STATS")
        self.log(f"   • پروکسی‌های فعال: {self.stats['active_proxies_found']:,}", "STATS")
        self.log(f"   • پروکسی‌های غیرفعال: {self.stats['inactive_proxies']:,}", "STATS")
        
        self.log(f"\n🔄 پردازش:", "STATS")
        self.log(f"   • پروکسی‌های اضافه شده: {self.stats['proxies_added']:,}", "STATS")
        self.log(f"   • پروکسی‌های حذف شده (قدیمی): {self.stats['proxies_removed']:,}", "STATS")
        self.log(f"   • پروکسی‌های تکراری: {self.stats['duplicates_found']:,}", "STATS")
        
        self.log(f"\n🌐 بررسی IP:", "STATS")
        self.log(f"   • بررسی‌های IP انجام شده: {self.stats['ip_checks']:,}", "STATS")
        self.log(f"   • استفاده از کش IP: {self.stats['ip_cache_hits']:,}", "STATS")
        self.log(f"   • درخواست‌های API: {self.stats['api_requests']:,}", "STATS")
        self.log(f"   • خطاهای API: {self.stats['api_failures']:,}", "STATS")
        
        self.log(f"\n🗑️  مدیریت فایل‌ها:", "STATS")
        self.log(f"   • لاگ‌های قدیمی حذف شده: {self.stats['old_logs_deleted']}", "STATS")
        
        self.log("="*80, "STATS")
    
    def close(self):
        """بستن فایل‌های لاگ"""
        self.log_fd.close()
        self.console_log_fd.close()

class IranProxyManager:
    def __init__(self, config_path: str = "output/config.yaml"):
        self.config_path = config_path
        self.logger = Logger()
        self.config = self.load_config()
        self.failed_sources = []
        self.ip_cache = {}
        self.lock = threading.Lock()
        
        # منابع اصلی
        self.SOURCES = [
            ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vmess.txt", "vmess", "github-vmess"),
            ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/vless.txt", "vless", "github-vless"),
            ("https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/splitted/ss.txt", "ss", "github-ss"),
            ("https://raw.githubusercontent.com/iranxray/hope/main/singbox", "vless", "github-hope"),
            ("https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/singbox", "vless", "github-telegram"),
            ("https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sb", "ss", "github-ss-aggr"),
            ("https://raw.githubusercontent.com/freefq/free/master/v2", "vmess", "github-freefq"),
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=IR", "socks5", "proxyscrape-socks5"),
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country=IR", "http", "proxyscrape-http"),
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&country=IR", "http", "proxyscrape-https"),
            ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5", "github-socks5"),
            ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "socks5", "github-hookzof"),
            ("https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", "mixed", "github-nowalls"),
            ("https://raw.githubusercontent.com/BlueSkyXN/9.DDFHP/main/1", "mixed", "github-ddfhp"),
            ("https://proxyhub.me/en/ir-http-proxy-list.html", "html-http", "proxyhub-http"),
            ("https://proxyhub.me/en/ir-sock5-proxy-list.html", "html-socks5", "proxyhub-socks5"),
            ("https://www.proxydocker.com/en/socks5-list/country/Iran", "html-socks5", "proxydocker-socks5"),
            ("https://www.proxydocker.com/en/proxylist/search?need=all&type=http-https&anonymity=all&port=&country=Iran&city=&state=all", "html-http", "proxydocker-http"),
            ("https://www.freeproxy.world/?type=http&anonymity=&country=IR", "html-http", "freeproxy-http"),
            ("https://www.freeproxy.world/?type=socks5&anonymity=&country=IR", "html-socks5", "freeproxy-socks5"),
            # منابع اضطراری
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all", "http", "emergency-http"),
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all", "socks5", "emergency-socks5"),
            ("https://raw.githubusercontent.com/freefq/free/master/v2", "vmess", "emergency-vmess"),
        ]
        
        # سرویس‌های بررسی IP
        self.IP_CHECK_SERVICES = [
            {'name': 'ip-api.com', 'url': 'http://ip-api.com/json/{ip}?fields=status,countryCode,query', 'field': 'countryCode', 'timeout': 3, 'max_retries': 2},
            {'name': 'ipapi.co', 'url': 'https://ipapi.co/{ip}/country/', 'field': 'text', 'timeout': 3, 'max_retries': 2},
            {'name': 'ipinfo.io', 'url': 'https://ipinfo.io/{ip}/country', 'field': 'text', 'timeout': 3, 'max_retries': 2},
        ]
        
        # User-Agent های متنوع
        self.USER_AGENTS = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "FacebookExternalHit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
            "Twitterbot/1.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "curl/7.88.1",
            "Wget/1.21.4",
        ]
    
    def __del__(self):
        self.logger.close()
    
    def load_config(self) -> Dict[str, Any]:
        """بارگذاری فایل کانفیگ"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():
                        config = yaml.safe_load(content)
                        if config and 'proxies' in config:
                            self.logger.log(f"فایل کانفیگ با {len(config['proxies'])} پروکسی بارگذاری شد")
                            return config
            self.logger.log("فایل کانفیگ یافت نشد. ایجاد فایل جدید...")
            return {"proxies": [], "metadata": {}}
        except Exception as e:
            self.logger.log(f"خطا در بارگذاری کانفیگ: {e}", "ERROR")
            return {"proxies": [], "metadata": {}}
    
    def save_config(self):
        """ذخیره فایل کانفیگ با تصحیح alterId"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            cleaned_proxies = []
            for proxy in self.config.get('proxies', []):
                if not all(key in proxy for key in ['server', 'port', 'type', 'added_date']):
                    continue
                
                cleaned_proxy = {
                    'name': proxy.get('name', f"{proxy['server']}:{proxy['port']}"),
                    'type': str(proxy['type']),
                    'server': str(proxy['server']),
                    'port': int(proxy['port']),
                    'added_date': str(proxy['added_date']),
                    'last_checked': str(proxy.get('last_checked', proxy['added_date'])),
                    'is_active': bool(proxy.get('is_active', True)),
                    'country': str(proxy.get('country', 'IR')),
                }
                
                # فیلدهای اختیاری استاندارد
                optional_fields = ['ping', 'source', 'uuid', 'cipher', 'password', 'network', 'tls']
                for field in optional_fields:
                    if field in proxy:
                        cleaned_proxy[field] = proxy[field]
                
                # تصحیح alterld به alterId (حل مشکل کلاینت‌های اندروید)
                if 'alterld' in proxy:  # اشتباه تایپی با حرف L
                    cleaned_proxy['alterId'] = proxy['alterld']
                elif 'alterId' in proxy:  # درست
                    cleaned_proxy['alterId'] = proxy['alterId']
                elif cleaned_proxy['type'] == 'vmess':
                    cleaned_proxy['alterId'] = 0  # مقدار پیش‌فرض
                
                # سایر فیلدهای خاص
                if 'ws-opts' in proxy:
                    cleaned_proxy['ws-opts'] = proxy['ws-opts']
                
                cleaned_proxies.append(cleaned_proxy)
            
            metadata = {
                'total_count': len(cleaned_proxies),
                'active_count': len([p for p in cleaned_proxies if p['is_active']]),
                'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'retention_days': 3,
                'min_proxies': 50,
                'sources_used': len(self.SOURCES),
                'log_retention_days': 14,
                'log_file': self.logger.log_file
            }
            
            final_config = {'proxies': cleaned_proxies, 'metadata': metadata}
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(final_config, f, 
                         default_flow_style=False, 
                         allow_unicode=True, 
                         sort_keys=False,
                         indent=2)
            
            self.logger.log(f"فایل کانفیگ ذخیره شد ({len(cleaned_proxies)} پروکسی)")
            return True
        except Exception as e:
            self.logger.log(f"خطا در ذخیره کانفیگ: {e}", "ERROR")
            return False
    
    def is_alive(self, ip: str, port: int, timeout: int = 5) -> Tuple[bool, int]:
        """بررسی فعال بودن پروکسی"""
        try:
            start = time.time()
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            ping = int((time.time() - start) * 1000)
            if ping > 0:
                self.logger.update_stat('active_proxies_found')
            return True, ping
        except:
            self.logger.update_stat('inactive_proxies')
            return False, 0
    
    def is_private_ip(self, ip: str) -> bool:
        """بررسی IP خصوصی"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),
            ('169.254.0.0', '169.254.255.255'),
        ]
        
        ip_int = self.ip_to_int(ip)
        for start, end in private_ranges:
            if ip_int >= self.ip_to_int(start) and ip_int <= self.ip_to_int(end):
                return True
        return False
    
    def ip_to_int(self, ip: str) -> int:
        """تبدیل IP به عدد صحیح"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    def check_ip_service(self, service: dict, ip: str) -> Optional[str]:
        """بررسی IP با یک سرویس خاص"""
        self.logger.update_stat('api_requests')
        
        for attempt in range(service['max_retries']):
            try:
                url = service['url'].format(ip=ip)
                headers = self.get_headers()
                
                response = requests.get(url, timeout=service['timeout'], headers=headers)
                
                if response.status_code == 200:
                    if service['field'] == 'text':
                        country = response.text.strip()
                        if len(country) == 2:
                            return country
                    else:
                        data = response.json()
                        if service['field'] in data:
                            country = data[service['field']]
                            if country and len(country) == 2:
                                return country
                
                if response.status_code == 429:
                    time.sleep(3)
                    
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue
        
        self.logger.update_stat('api_failures')
        return None
    
    def get_headers(self):
        """ایجاد headers با User-Agent تصادفی"""
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
            "Referer": "https://www.google.com/"
        }
    
    def check_ip_country(self, ip: str) -> Optional[str]:
        """بررسی کشور IP با استفاده از سرویس‌های آنلاین با fallback"""
        with self.lock:
            if ip in self.ip_cache:
                self.logger.update_stat('ip_cache_hits')
                return self.ip_cache[ip]
        
        self.logger.update_stat('ip_checks')
        
        if self.is_private_ip(ip):
            with self.lock:
                self.ip_cache[ip] = None
            return None
        
        country = None
        
        for service in self.IP_CHECK_SERVICES:
            result = self.check_ip_service(service, ip)
            if result:
                country = result
                break
        
        with self.lock:
            self.ip_cache[ip] = country
        
        return country
    
    def ip_is_ir(self, ip: str) -> bool:
        """بررسی ایرانی بودن IP"""
        country = self.check_ip_country(ip)
        is_iran = country == 'IR'
        
        if country and not is_iran:
            self.logger.update_stat('non_iranian_proxies')
        
        return is_iran
    
    def parse_ss(self, url: str) -> Dict[str, Any]:
        """پارس کردن لینک Shadowsocks"""
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
    
    def fetch_html_proxies(self, url: str, proxy_type: str, source_name: str) -> List[Tuple[str, str, str]]:
        """استخراج پروکسی از صفحات HTML"""
        proxies = []
        try:
            headers = self.get_headers()
            
            time.sleep(random.uniform(2, 5))
            
            res = requests.get(url, headers=headers, timeout=20)
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
                    if ip and port:
                        proxies.append((ip, port, "socks5" if "socks5" in proxy_type else "http"))
            else:
                rows = soup.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) < 2:
                        continue
                    ip, port = cols[0].text.strip(), cols[1].text.strip()
                    if ip and port and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        proxies.append((ip, port, "socks5" if "socks5" in proxy_type else "http"))

            return proxies
        except Exception:
            return []
    
    def fetch_source_proxies(self, url: str, ptype: str, source_name: str, source_index: int, total_sources: int) -> List[Dict[str, Any]]:
        """دریافت پروکسی از یک منبع خاص"""
        proxies = []
        
        # نمایش اطلاعات فعلی
        current_total = self.logger.stats['total_proxies_received']
        current_iranian = self.logger.stats['iranian_proxies']
        self.logger.log(f"[{source_index}/{total_sources}] 🔍 دریافت از {source_name}", "INFO")
        self.logger.log(f"   📊 وضعیت فعلی: [{current_iranian}/{current_total}]", "DEBUG")
        
        # تلاش‌های متعدد
        for attempt in range(3):
            try:
                self.logger.update_stat('sources_used')
                
                headers = self.get_headers()
                
                delay = random.uniform(2, 4) if attempt > 0 else random.uniform(1, 2)
                time.sleep(delay)
                
                response = requests.get(url, timeout=25, headers=headers)
                
                if response.status_code == 200:
                    break
                elif response.status_code == 403:
                    self.logger.log(f"   ⚠️ دسترسی ممنوع (403) - تلاش {attempt+1}/3", "WARNING")
                    if attempt < 2:
                        time.sleep(random.uniform(5, 8))
                        continue
                    else:
                        self.logger.log(f"   ❌ بعد از ۳ تلاش موفق نشدیم", "ERROR")
                        self.failed_sources.append(url)
                        self.logger.update_stat('sources_failed')
                        return []
                else:
                    if attempt < 2:
                        time.sleep(3)
                        continue
                    else:
                        self.failed_sources.append(url)
                        self.logger.update_stat('sources_failed')
                        return []
                        
            except requests.exceptions.Timeout:
                if attempt < 2:
                    time.sleep(5)
                    continue
                else:
                    self.failed_sources.append(url)
                    self.logger.update_stat('sources_failed')
                    return []
            except Exception:
                if attempt < 2:
                    time.sleep(3)
                    continue
                else:
                    self.failed_sources.append(url)
                    self.logger.update_stat('sources_failed')
                    return []
        
        # اگر منبع HTML است
        if ptype.startswith("html-"):
            html_proxies = self.fetch_html_proxies(url, ptype, source_name)
            total_lines = len(html_proxies)
            self.logger.update_stat('total_proxies_received', total_lines)
            
            added_count = 0
            skipped_non_iran = 0
            
            for idx, (ip, port, proto) in enumerate(html_proxies, 1):
                # نمایش هر ۵ پروکسی
                if idx % 5 == 0:
                    current_total = self.logger.stats['total_proxies_received']
                    current_iranian = self.logger.stats['iranian_proxies']
                    self.logger.log(f"   🔄 [{source_index}/{total_sources}] | [{current_iranian}/{current_total}] - پردازش پروکسی {idx}", "DEBUG")
                
                if not self.ip_is_ir(ip):
                    skipped_non_iran += 1
                    continue
                
                self.logger.update_stat('iranian_proxies')
                alive, ping = self.is_alive(ip, int(port))
                
                proxy_data = {
                    'name': f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}",
                    'type': proto,
                    'server': ip,
                    'port': int(port),
                    'added_date': datetime.now().strftime('%Y-%m-%d'),
                    'last_checked': datetime.now().strftime('%Y-%m-%d'),
                    'is_active': alive,
                    'country': 'IR',
                    'ping': ping if alive else 0,
                    'source': url,
                    'source_name': source_name
                }
                proxies.append(proxy_data)
                added_count += 1
            
            # نمایش نتایج
            current_total = self.logger.stats['total_proxies_received']
            current_iranian = self.logger.stats['iranian_proxies']
            self.logger.log(f"[{source_index}/{total_sources}] ✅ {source_name}: {added_count} پروکسی ایرانی", "INFO")
            self.logger.log(f"   📊 وضعیت نهایی: [{current_iranian}/{current_total}]", "DEBUG")
            
            return proxies
        
        # برای منابع متنی/API
        lines = response.text.strip().splitlines()
        total_lines = len(lines)
        self.logger.update_stat('total_proxies_received', total_lines)
        
        self.logger.log(f"   📄 {total_lines} خط دریافت شد", "DEBUG")
        
        added_count = 0
        skipped_non_iran = 0
        skipped_invalid = 0
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # نمایش هر ۱۰ خط
            if line_num % 10 == 0:
                current_total = self.logger.stats['total_proxies_received']
                current_iranian = self.logger.stats['iranian_proxies']
                self.logger.log(f"   🔄 [{source_index}/{total_sources}] | [{current_iranian}/{current_total}] - خط {line_num}/{total_lines}", "DEBUG")
            
            try:
                # VMESS
                if ptype == "vmess" and line.startswith("vmess://"):
                    decoded = base64.b64decode(line[8:] + "==").decode()
                    conf = json.loads(decoded)
                    ip = conf.get("add")
                    port = conf.get("port")
                    
                    if not ip or not port:
                        skipped_invalid += 1
                        continue
                    
                    if not self.ip_is_ir(ip):
                        skipped_non_iran += 1
                        continue
                    
                    self.logger.update_stat('iranian_proxies')
                    alive, ping = self.is_alive(ip, port)
                    
                    proxy_data = {
                        'name': f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}",
                        'type': 'vmess',
                        'server': ip,
                        'port': int(port),
                        'uuid': conf.get("id"),
                        'alterId': int(conf.get("aid", 0)),
                        'cipher': conf.get("cipher", "auto"),
                        'tls': conf.get("tls") == "tls",
                        'network': conf.get("net", "tcp"),
                        'added_date': datetime.now().strftime('%Y-%m-%d'),
                        'last_checked': datetime.now().strftime('%Y-%m-%d'),
                        'is_active': alive,
                        'country': 'IR',
                        'ping': ping if alive else 0,
                        'source': url,
                        'source_name': source_name
                    }
                    
                    if conf.get("net") == "ws":
                        proxy_data["ws-opts"] = {
                            'path': conf.get("path", "/"),
                            'headers': {'Host': conf.get("host", "")}
                        }
                    
                    proxies.append(proxy_data)
                    added_count += 1
                
                # VLESS
                elif ptype == "vless" and line.startswith("vless://"):
                    conf = self.parse_vless(line)
                    if not conf:
                        skipped_invalid += 1
                        continue
                    
                    ip = conf.get("server")
                    
                    if not ip or not self.ip_is_ir(ip):
                        skipped_non_iran += 1
                        continue
                    
                    self.logger.update_stat('iranian_proxies')
                    alive, ping = self.is_alive(ip, conf["port"])
                    conf["added_date"] = datetime.now().strftime('%Y-%m-%d')
                    conf["last_checked"] = datetime.now().strftime('%Y-%m-%d')
                    conf["is_active"] = alive
                    conf["country"] = 'IR'
                    conf["ping"] = ping if alive else 0
                    conf["source"] = url
                    conf["source_name"] = source_name
                    conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
                    
                    proxies.append(conf)
                    added_count += 1
                
                # Shadowsocks
                elif ptype == "ss" and line.startswith("ss://"):
                    conf = self.parse_ss(line)
                    if not conf:
                        skipped_invalid += 1
                        continue
                    
                    ip = conf.get("server")
                    
                    if not ip or not self.ip_is_ir(ip):
                        skipped_non_iran += 1
                        continue
                    
                    self.logger.update_stat('iranian_proxies')
                    alive, ping = self.is_alive(ip, conf["port"])
                    conf["added_date"] = datetime.now().strftime('%Y-%m-%d')
                    conf["last_checked"] = datetime.now().strftime('%Y-%m-%d')
                    conf["is_active"] = alive
                    conf["country"] = 'IR'
                    conf["ping"] = ping if alive else 0
                    conf["source"] = url
                    conf["source_name"] = source_name
                    conf["name"] = f"{conf['server']}:{conf['port']} ({ping}ms)" if alive else f"{conf['server']}:{conf['port']}"
                    
                    proxies.append(conf)
                    added_count += 1
                
                # HTTP/SOCKS5/MIXED
                elif ":" in line and ptype in ["http", "socks5", "mixed"]:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        port = parts[1].strip()
                        
                        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                            skipped_invalid += 1
                            continue
                        
                        proto = ptype
                        if proto == "mixed":
                            proto = "http" if len(parts) == 2 else "socks5"
                        
                        if not self.ip_is_ir(ip):
                            skipped_non_iran += 1
                            continue
                        
                        self.logger.update_stat('iranian_proxies')
                        alive, ping = self.is_alive(ip, int(port))
                        
                        proxy_data = {
                            'name': f"{ip}:{port} ({ping}ms)" if alive else f"{ip}:{port}",
                            'type': proto,
                            'server': ip,
                            'port': int(port),
                            'added_date': datetime.now().strftime('%Y-%m-%d'),
                            'last_checked': datetime.now().strftime('%Y-%m-%d'),
                            'is_active': alive,
                            'country': 'IR',
                            'ping': ping if alive else 0,
                            'source': url,
                            'source_name': source_name
                        }
                        proxies.append(proxy_data)
                        added_count += 1
                    else:
                        skipped_invalid += 1
            
            except Exception:
                skipped_invalid += 1
                continue
        
        # نمایش نتایج
        current_total = self.logger.stats['total_proxies_received']
        current_iranian = self.logger.stats['iranian_proxies']
        self.logger.log(f"[{source_index}/{total_sources}] ✅ {source_name}: {added_count} پروکسی ایرانی", "INFO")
        self.logger.log(f"   📊 وضعیت نهایی: [{current_iranian}/{current_total}] | نامعتبر: {skipped_invalid} | غیرایرانی: {skipped_non_iran}", "DEBUG")
        
        return proxies
    
    def fetch_all_proxies(self) -> List[Dict[str, Any]]:
        """دریافت همه پروکسی‌ها از منابع"""
        all_proxies = []
        seen_keys = set()
        
        total_sources = len(self.SOURCES)
        self.logger.log(f"\n📥 شروع دریافت پروکسی‌ها از {total_sources} منبع:")
        self.logger.log("=" * 70)
        
        for idx, (url, ptype, source_name) in enumerate(self.SOURCES, 1):
            proxies = self.fetch_source_proxies(url, ptype, source_name, idx, total_sources)
            
            # حذف تکراری‌ها
            filtered_proxies = []
            for proxy in proxies:
                key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}-{proxy.get('type', '')}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    filtered_proxies.append(proxy)
                else:
                    self.logger.update_stat('duplicates_found')
            
            all_proxies.extend(filtered_proxies)
            
            # تأخیر بین منابع
            if idx < total_sources:
                time.sleep(random.uniform(0.5, 1.5))
        
        self.logger.log("=" * 70)
        self.logger.log(f"📊 مجموع {len(all_proxies)} پروکسی ایرانی از {total_sources} منبع دریافت شد")
        return all_proxies
    
    def add_new_proxies(self, new_proxies: List[Dict[str, Any]]) -> Tuple[int, int]:
        """اضافه کردن پروکسی‌های جدید به لیست موجود"""
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
                self.logger.update_stat('proxies_added')
            else:
                duplicate_count += 1
                self.logger.update_stat('duplicates_found')
        
        return added_count, duplicate_count
    
    def should_remove_old_proxies(self) -> Tuple[bool, List[Dict], int]:
        """بررسی شرایط حذف پروکسی‌های قدیمی"""
        total_proxies = len(self.config.get('proxies', []))
        
        if total_proxies <= 50:
            return False, [], 0
        
        excess_count = total_proxies - 50
        
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
        
        old_proxies.sort(key=lambda x: datetime.strptime(x['added_date'], '%Y-%m-%d'))
        
        should_remove = len(old_proxies) > 0 and excess_count > 0
        
        return should_remove, old_proxies, excess_count
    
    def remove_old_proxies_with_conditions(self) -> int:
        """حذف پروکسی‌های قدیمی در صورت برقراری شرایط"""
        should_remove, old_proxies, excess_count = self.should_remove_old_proxies()
        
        if not should_remove:
            return 0
        
        old_keys_to_remove = set()
        for proxy in old_proxies[:excess_count]:
            key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}-{proxy.get('type', '')}"
            old_keys_to_remove.add(key)
        
        remaining_proxies = []
        removed_count = 0
        
        for proxy in self.config.get('proxies', []):
            key = f"{proxy.get('server', '')}:{proxy.get('port', 0)}-{proxy.get('type', '')}"
            
            if key in old_keys_to_remove and removed_count < excess_count:
                removed_count += 1
                self.logger.update_stat('proxies_removed')
                self.logger.log(f"   🗑️ حذف پروکسی قدیمی: {proxy.get('server')}:{proxy.get('port')} (تاریخ: {proxy.get('added_date')})", "INFO")
                continue
            
            remaining_proxies.append(proxy)
        
        self.config['proxies'] = remaining_proxies
        return removed_count
    
    def ensure_minimum_proxies(self):
        """اطمینان از وجود حداقل ۵۰ پروکسی فعال"""
        active_proxies = [p for p in self.config.get('proxies', []) if p.get('is_active', False)]
        
        if len(active_proxies) >= 50:
            self.logger.log(f"✅ {len(active_proxies)} پروکسی فعال موجود است (کافی است)")
            return
        
        needed = 50 - len(active_proxies)
        self.logger.log(f"⚠️ فقط {len(active_proxies)} پروکسی فعال داریم. نیاز به {needed} پروکسی بیشتر")
        
        self.logger.log("🔍 تلاش برای دریافت پروکسی‌های بیشتر از منابع اضطراری...")
        
        # استفاده از منابع اضطراری
        emergency_sources = [
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all", "http", "emergency-http"),
            ("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all", "socks5", "emergency-socks5"),
            ("https://raw.githubusercontent.com/freefq/free/master/v2", "vmess", "emergency-vmess"),
        ]
        
        original_sources = self.SOURCES.copy()
        self.SOURCES = emergency_sources
        
        new_emergency_proxies = self.fetch_all_proxies()
        added, _ = self.add_new_proxies(new_emergency_proxies)
        
        self.SOURCES = original_sources
        
        if added > 0:
            self.logger.log(f"✅ {added} پروکسی اضطراری اضافه شد")
        else:
            self.logger.log("❌ نتوانستیم پروکسی اضافی پیدا کنیم")
    
    def run(self) -> bool:
        """اجرای اصلی"""
        self.logger.log("=" * 80)
        self.logger.log("🚀 شروع فرآیند به‌روزرسانی پروکسی‌های ایرانی")
        self.logger.log(f"🌐 تعداد منابع: {len(self.SOURCES)} منبع")
        self.logger.log("🔍 سیستم: بررسی مستقیم IP از سرویس‌های آنلاین با fallback")
        self.logger.log("=" * 80)
        
        try:
            # 1. وضعیت اولیه
            initial_count = len(self.config.get('proxies', []))
            initial_active = len([p for p in self.config.get('proxies', []) 
                                 if p.get('is_active', False)])
            self.logger.log(f"📊 وضعیت اولیه:")
            self.logger.log(f"   • تعداد کل پروکسی‌ها: {initial_count}")
            self.logger.log(f"   • پروکسی‌های فعال: {initial_active}")
            self.logger.log(f"   • حداقل مورد نیاز: 50")
            
            # 2. دریافت پروکسی‌های جدید
            new_proxies = self.fetch_all_proxies()
            self.logger.log(f"\n📥 {len(new_proxies)} پروکسی ایرانی دریافت شد")
            
            # 3. اضافه کردن پروکسی‌های جدید
            added_count, duplicate_count = self.add_new_proxies(new_proxies)
            self.logger.log(f"\n➕ اضافه کردن پروکسی‌های جدید:")
            self.logger.log(f"   ✅ {added_count} پروکسی ایرانی جدید اضافه شد")
            if duplicate_count > 0:
                self.logger.log(f"   ⚠️ {duplicate_count} پروکسی تکراری نادیده گرفته شد")
            
            # 4. بررسی شرایط حذف
            self.logger.log(f"\n🗑️ بررسی شرایط حذف پروکسی‌های قدیمی:")
            total_after_add = len(self.config.get('proxies', []))
            self.logger.log(f"   تعداد پروکسی‌ها بعد از اضافه کردن: {total_after_add}")
            
            should_remove, old_proxies, excess_count = self.should_remove_old_proxies()
            
            if should_remove:
                self.logger.log(f"   ✓ شرط ۱: تعداد پروکسی‌ها ({total_after_add}) > ۵۰")
                self.logger.log(f"   ✓ شرط ۲: {len(old_proxies)} پروکسی قدیمی‌تر از ۳ روز")
                self.logger.log(f"   ⚡ هر دو شرط برقرار است → حذف قدیمی‌ها")
                
                removed_count = self.remove_old_proxies_with_conditions()
                if removed_count > 0:
                    self.logger.log(f"   ✅ {removed_count} پروکسی قدیمی حذف شدند")
            else:
                self.logger.log(f"   ⏸️ شرایط حذف برقرار نیست:")
                if total_after_add <= 50:
                    self.logger.log(f"     ✗ تعداد کل ({total_after_add}) ≤ ۵۰")
                if len(old_proxies) == 0:
                    self.logger.log(f"     ✗ پروکسی قدیمی‌تر از ۳ روز وجود ندارد")
            
            # 5. بررسی حداقل تعداد
            self.logger.log(f"\n📊 بررسی حداقل تعداد پروکسی...")
            self.ensure_minimum_proxies()
            
            # 6. ذخیره فایل
            self.logger.log(f"\n💾 ذخیره تغییرات...")
            if not self.save_config():
                self.logger.log("❌ خطا در ذخیره‌سازی!", "ERROR")
                return False
            
            # 7. نمایش آمار کامل
            self.logger.print_stats()
            
            # 8. گزارش نهایی
            final_count = len(self.config.get('proxies', []))
            final_active = len([p for p in self.config.get('proxies', []) 
                               if p.get('is_active', False)])
            
            self.logger.log("\n" + "=" * 80)
            self.logger.log("📈 گزارش نهایی")
            self.logger.log("=" * 80)
            self.logger.log(f"📊 تعداد کل پروکسی‌ها: {final_count}")
            self.logger.log(f"✅ پروکسی‌های فعال: {final_active}")
            self.logger.log(f"📈 تغییرات کل: {final_count - initial_count:+d} پروکسی")
            self.logger.log(f"📈 تغییرات فعال: {final_active - initial_active:+d} پروکسی")
            
            # گزارش منابع
            successful_sources = len(self.SOURCES) - len(self.failed_sources)
            self.logger.log(f"\n🌐 گزارش منابع:")
            self.logger.log(f"   • منابع موفق: {successful_sources}/{len(self.SOURCES)}")
            self.logger.log(f"   • منابع شکست خورده: {len(self.failed_sources)}")
            
            if final_active >= 50:
                self.logger.log(f"\n✅ موفقیت: {final_active} پروکسی ایرانی فعال موجود است")
            else:
                self.logger.log(f"\n⚠️ هشدار: فقط {final_active} پروکسی ایرانی فعال موجود است")
            
            self.logger.log(f"\n📁 فایل لاگ: {self.logger.log_file}")
            self.logger.log(f"📁 فایل کانفیگ: {self.config_path}")
            self.logger.log("=" * 80)
            
            return True
            
        except KeyboardInterrupt:
            self.logger.log("\n\n⏹️ عملیات توسط کاربر متوقف شد", "WARNING")
            return False
        except Exception as e:
            self.logger.log(f"\n❌ خطای غیرمنتظره: {e}", "ERROR")
            import traceback
            self.logger.log(traceback.format_exc(), "ERROR")
            return False

def main():
    """تابع اصلی"""
    print("🔧 مدیر پروکسی‌های ایرانی - سیستم بررسی مستقیم IP")
    print("📅 " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print(f"🌐 {len(IranProxyManager().SOURCES)} منبع")
    print("🔍 استفاده از سرویس‌های آنلاین با سیستم fallback")
    
    manager = IranProxyManager()
    success = manager.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
