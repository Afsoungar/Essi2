#!/usr/bin/env python3
"""
اسکریپت مدیریت پروکسی‌های ایرانی
ویژگی‌ها:
- دریافت پروکسی‌های جدید از منابع مختلف
- حذف تکراری‌ها در سه سطح
- مدیریت پروکسی‌های قدیمی بر اساس دو شرط همزمان
- حفظ حداقل 50 پروکسی فعال
"""

import yaml
import requests
from datetime import datetime, timedelta
import os
import sys
from typing import List, Dict, Any, Tuple, Set

class ProxyManager:
    def __init__(self, config_path: str = "output/config.yaml"):
        """
        مقداردهی اولیه مدیر پروکسی
        
        Args:
            config_path: مسیر فایل پیکربندی YAML
        """
        self.config_path = config_path
        self.config = self.load_config()
        
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
                'max_proxies': None,
                'description': 'لیست پروکسی‌های ایرانی - به‌روزرسانی خودکار'
            }
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True, 
                         sort_keys=False, width=120)
            
            print(f"💾 فایل کانفیگ ذخیره شد ({len(self.config.get('proxies', []))} پروکسی)")
            return True
        except Exception as e:
            print(f"❌ خطا در ذخیره کانفیگ: {e}")
            return False
    
    def normalize_proxy_address(self, proxy_address: str) -> str:
        """
        نرمال‌سازی آدرس پروکسی
        
        Args:
            proxy_address: آدرس پروکسی خام
            
        Returns:
            آدرس پروکسی نرمال‌سازی شده
        """
        if not proxy_address:
            return ""
        
        # حذف فضاهای اضافه
        proxy_address = proxy_address.strip()
        
        # حذف پروتکل‌ها
        for protocol in ['http://', 'https://', 'socks4://', 'socks5://', 'socks://']:
            if proxy_address.lower().startswith(protocol):
                proxy_address = proxy_address[len(protocol):]
        
        # تقسیم به IP و پورت
        parts = proxy_address.split(':')
        if len(parts) == 2:
            ip, port = parts
            # حذف فضاها از IP و پورت
            ip = ip.strip()
            port = port.strip()
            # بازگرداندن به فرمت استاندارد
            return f"{ip}:{port}".lower()
        
        return proxy_address.lower()
    
    def is_valid_proxy(self, proxy_address: str) -> bool:
        """
        بررسی اعتبار فرمت پروکسی
        
        Args:
            proxy_address: آدرس پروکسی
            
        Returns:
            True اگر فرمت معتبر باشد
        """
        try:
            normalized = self.normalize_proxy_address(proxy_address)
            
            # بررسی وجود دو بخش (IP:Port)
            if ':' not in normalized:
                return False
            
            ip, port = normalized.split(':')
            
            # بررسی پورت
            try:
                port_num = int(port)
                if not (1 <= port_num <= 65535):
                    return False
            except ValueError:
                return False
            
            # بررسی IP (فرم‌های مختلف)
            ip_parts = ip.split('.')
            
            # IPv4 استاندارد
            if len(ip_parts) == 4:
                for part in ip_parts:
                    if not part.isdigit():
                        return False
                    num = int(part)
                    if not (0 <= num <= 255):
                        return False
                return True
            
            # IPv6 (فعلاً ساده‌سازی شده)
            if '[' in ip and ']' in ip:  # فرمت [IPv6]:port
                return True
            
            # سایر فرمت‌ها
            return True
            
        except Exception:
            return False
    
    def fetch_new_proxies(self) -> Set[str]:
        """
        دریافت پروکسی‌های جدید از منابع مختلف
        
        Returns:
            مجموعه‌ای از پروکسی‌های منحصربه‌فرد
        """
        sources = [
            {
                'url': 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
                'type': 'http'
            },
            {
                'url': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                'type': 'http'
            },
            {
                'url': 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=IR',
                'type': 'http'
            },
            {
                'url': 'https://openproxylist.xyz/http.txt',
                'type': 'http'
            },
            {
                'url': 'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
                'type': 'http'
            },
        ]
        
        new_proxies_set = set()
        successful_sources = 0
        
        print("\n📥 دریافت پروکسی‌های جدید از منابع:")
        print("-" * 50)
        
        for i, source in enumerate(sources, 1):
            try:
                print(f"🔍 منبع {i}/{len(sources)}: {source['url'][:60]}...")
                
                response = requests.get(
                    source['url'],
                    timeout=15,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                )
                
                if response.status_code == 200:
                    lines = response.text.strip().split('\n')
                    added_from_source = 0
                    
                    for line in lines:
                        line = line.strip()
                        if line and self.is_valid_proxy(line):
                            normalized = self.normalize_proxy_address(line)
                            if normalized not in new_proxies_set:
                                new_proxies_set.add(normalized)
                                added_from_source += 1
                    
                    if added_from_source > 0:
                        print(f"   ✅ {added_from_source} پروکسی جدید")
                        successful_sources += 1
                    else:
                        print(f"   ℹ️  هیچ پروکسی جدیدی")
                        
                else:
                    print(f"   ❌ خطا HTTP {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"   ⏰ تایم‌اوت در اتصال")
            except requests.exceptions.ConnectionError:
                print(f"   🔌 خطا در اتصال")
            except Exception as e:
                print(f"   ⚠️  خطا: {str(e)[:40]}")
        
        print("-" * 50)
        print(f"📊 {len(new_proxies_set)} پروکسی منحصربه‌فرد از {successful_sources} منبع دریافت شد")
        
        return new_proxies_set
    
    def get_existing_proxies_set(self) -> Set[str]:
        """
        دریافت مجموعه پروکسی‌های موجود
        
        Returns:
            مجموعه‌ای از آدرس‌های پروکسی نرمال‌سازی شده
        """
        existing_set = set()
        for proxy in self.config.get('proxies', []):
            if 'address' in proxy:
                normalized = self.normalize_proxy_address(proxy['address'])
                existing_set.add(normalized)
        return existing_set
    
    def add_new_proxies(self, new_proxies_set: Set[str]) -> Tuple[int, List[str]]:
        """
        اضافه کردن پروکسی‌های جدید به لیست
        
        Args:
            new_proxies_set: مجموعه پروکسی‌های جدید
            
        Returns:
            (تعداد اضافه شده, لیست پروکسی‌های اضافه شده)
        """
        existing_set = self.get_existing_proxies_set()
        
        # یافتن پروکسی‌های منحصربه‌فرد
        unique_proxies = new_proxies_set - existing_set
        
        if not unique_proxies:
            return 0, []
        
        added_count = 0
        added_list = []
        today_str = datetime.now().strftime('%Y-%m-%d')
        
        for proxy_address in unique_proxies:
            proxy_data = {
                'address': proxy_address,
                'added_date': today_str,
                'last_checked': today_str,
                'is_active': True,
                'country': self.detect_country(proxy_address),
                'source': 'auto',
                'protocol': 'http'  # می‌توانید از روی پورت تشخیص دهید
            }
            
            self.config.setdefault('proxies', []).append(proxy_data)
            added_count += 1
            added_list.append(proxy_address)
            
            # نمایش پیشرفت برای تعداد زیاد
            if added_count % 20 == 0:
                print(f"   📝 {added_count} پروکسی اضافه شد...")
        
        return added_count, added_list
    
    def detect_country(self, proxy_address: str) -> str:
        """
        تشخیص کشور پروکسی (ساده‌سازی شده)
        
        Args:
            proxy_address: آدرس پروکسی
            
        Returns:
            کد کشور
        """
        # این بخش را می‌توانید با APIهای تشخیص IP کامل کنید
        # فعلاً به صورت ساده:
        try:
            ip = proxy_address.split(':')[0]
            # تشخیص IPهای ایرانی (لیست محدود)
            iran_ranges = [
                '5.', '31.', '37.', '46.', '62.', '77.', '78.', 
                '79.', '85.', '86.', '87.', '89.', '91.', '92.',
                '93.', '94.', '95.', '98.', '185.', '188.', '212.'
            ]
            
            for ir_range in iran_ranges:
                if ip.startswith(ir_range):
                    return 'IR'
                    
            return 'UNKNOWN'
        except:
            return 'UNKNOWN'
    
    def should_remove_old_proxies(self) -> Tuple[bool, List[Dict], int]:
        """
        بررسی شرایط حذف پروکسی‌های قدیمی
        
        Returns:
            (آیا حذف کنیم؟, لیست پروکسی‌های قدیمی, تعداد اضافی)
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
        
        Returns:
            تعداد پروکسی‌های حذف شده
        """
        should_remove, old_proxies, excess_count = self.should_remove_old_proxies()
        
        if not should_remove:
            return 0
        
        # ایجاد مجموعه از آدرس‌های پروکسی‌های قدیمی برای حذف سریع‌تر
        old_proxies_to_remove = set()
        for proxy in old_proxies[:excess_count]:  # فقط به تعداد اضافی
            if 'address' in proxy:
                old_proxies_to_remove.add(self.normalize_proxy_address(proxy['address']))
        
        # فیلتر کردن لیست پروکسی‌ها
        remaining_proxies = []
        removed_count = 0
        
        for proxy in self.config.get('proxies', []):
            if 'address' in proxy:
                normalized = self.normalize_proxy_address(proxy['address'])
                
                # اگر پروکسی در لیست حذف بود و هنوز نیاز به حذف داریم
                if normalized in old_proxies_to_remove and removed_count < excess_count:
                    removed_count += 1
                    continue  # حذف این پروکسی
            
            remaining_proxies.append(proxy)
        
        # به‌روزرسانی لیست
        self.config['proxies'] = remaining_proxies
        
        return removed_count
    
    def ensure_minimum_proxies(self) -> int:
        """
        اطمینان از وجود حداقل ۵۰ پروکسی
        
        Returns:
            تعداد پروکسی‌های اضافه شده
        """
        current_count = len(self.config.get('proxies', []))
        
        if current_count >= 50:
            return 0
        
        needed = 50 - current_count
        print(f"\n⚠️  تعداد پروکسی‌ها ({current_count}) کمتر از ۵۰ است")
        print(f"🔍 نیاز به {needed} پروکسی جدید")
        
        # منابع اضطراری
        emergency_sources = [
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
            "https://www.proxy-list.download/api/v1/get?type=http",
            "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc",
        ]
        
        existing_set = self.get_existing_proxies_set()
        added = 0
        
        print("\n🚨 دریافت پروکسی‌های اضطراری:")
        print("-" * 40)
        
        for source in emergency_sources:
            if added >= needed:
                break
                
            try:
                print(f"🔧 منبع اضطراری: {source[:50]}...")
                response = requests.get(source, timeout=20)
                
                if response.status_code == 200:
                    lines = []
                    
                    # پردازش بر اساس فرمت منبع
                    if 'proxylist.geonode.com' in source:
                        # فرمت JSON
                        try:
                            data = response.json()
                            for proxy in data.get('data', []):
                                address = f"{proxy.get('ip')}:{proxy.get('port')}"
                                if address:
                                    lines.append(address)
                        except:
                            lines = response.text.split('\n')
                    else:
                        # فرمت متنی ساده
                        lines = response.text.split('\n')
                    
                    for line in lines:
                        if added >= needed:
                            break
                            
                        line = line.strip()
                        if line and self.is_valid_proxy(line):
                            normalized = self.normalize_proxy_address(line)
                            
                            if normalized not in existing_set:
                                proxy_data = {
                                    'address': normalized,
                                    'added_date': datetime.now().strftime('%Y-%m-%d'),
                                    'last_checked': datetime.now().strftime('%Y-%m-%d'),
                                    'is_active': True,
                                    'country': 'UNKNOWN',
                                    'source': 'emergency',
                                    'protocol': 'http'
                                }
                                
                                self.config['proxies'].append(proxy_data)
                                existing_set.add(normalized)
                                added += 1
                                
                    if added > 0:
                        print(f"   ➕ {added} پروکسی اضافه شد")
                        
            except Exception as e:
                print(f"   ❌ خطا: {str(e)[:30]}")
        
        print("-" * 40)
        
        if added > 0:
            print(f"✅ {added} پروکسی اضطراری اضافه شد")
        else:
            print("❌ نتوانستیم پروکسی اضطراری اضافه کنیم")
            
        return added
    
    def analyze_proxies(self) -> Dict[str, Any]:
        """
        تحلیل و ارائه آمار پروکسی‌ها
        
        Returns:
            دیکشنری حاوی آمار
        """
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
            
            # آمار کشور
            country = proxy.get('country', 'UNKNOWN')
            country_stats[country] = country_stats.get(country, 0) + 1
        
        # مرتب‌سازی کشورها
        sorted_countries = sorted(country_stats.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'total': len(proxies),
            'age_stats': age_stats,
            'country_stats': dict(sorted_countries[:5]),  # 5 کشور اول
            'oldest_date': self.get_oldest_proxy_date(),
            'newest_date': self.get_newest_proxy_date()
        }
    
    def get_oldest_proxy_date(self) -> str:
        """دریافت تاریخ قدیمی‌ترین پروکسی"""
        try:
            dates = []
            for proxy in self.config.get('proxies', []):
                if 'added_date' in proxy:
                    dates.append(datetime.strptime(proxy['added_date'], '%Y-%m-%d'))
            
            if dates:
                return min(dates).strftime('%Y-%m-%d')
        except:
            pass
        return 'N/A'
    
    def get_newest_proxy_date(self) -> str:
        """دریافت تاریخ جدیدترین پروکسی"""
        try:
            dates = []
            for proxy in self.config.get('proxies', []):
                if 'added_date' in proxy:
                    dates.append(datetime.strptime(proxy['added_date'], '%Y-%m-%d'))
            
            if dates:
                return max(dates).strftime('%Y-%m-%d')
        except:
            pass
        return 'N/A'
    
    def check_for_duplicates(self) -> List[str]:
        """
        بررسی پروکسی‌های تکراری در لیست
        
        Returns:
            لیست آدرس‌های تکراری
        """
        seen = set()
        duplicates = []
        
        for proxy in self.config.get('proxies', []):
            if 'address' in proxy:
                normalized = self.normalize_proxy_address(proxy['address'])
                if normalized in seen:
                    duplicates.append(proxy['address'])
                else:
                    seen.add(normalized)
        
        return duplicates
    
    def run(self) -> bool:
        """
        اجرای اصلی اسکریپت
        
        Returns:
            True اگر موفقیت‌آمیز بود
        """
        print("=" * 70)
        print("🚀 شروع فرآیند به‌روزرسانی پروکسی‌های ایرانی")
        print("=" * 70)
        
        try:
            # 1. وضعیت اولیه
            initial_count = len(self.config.get('proxies', []))
            print(f"\n📊 وضعیت اولیه:")
            print(f"   • تعداد پروکسی‌ها: {initial_count}")
            print(f"   • حداقل مورد نیاز: 50")
            
            # 2. دریافت پروکسی‌های جدید
            new_proxies_set = self.fetch_new_proxies()
            
            # 3. اضافه کردن پروکسی‌های جدید
            print(f"\n➕ اضافه کردن پروکسی‌های جدید:")
            added_count, added_list = self.add_new_proxies(new_proxies_set)
            
            if added_count > 0:
                print(f"   ✅ {added_count} پروکسی جدید اضافه شد")
                # نمایش نمونه
                if added_count <= 5:
                    for addr in added_list[:3]:
                        print(f"     📍 {addr}")
                else:
                    print(f"     📍 {added_list[0]}")
                    print(f"     📍 {added_list[1]}")
                    print(f"     📍 ... و {added_count - 2} پروکسی دیگر")
            else:
                print(f"   ℹ️  همه پروکسی‌ها از قبل موجود بودند")
            
            # 4. بررسی شرایط حذف
            print(f"\n🗑️  بررسی شرایط حذف پروکسی‌های قدیمی:")
            should_remove, old_proxies, excess_count = self.should_remove_old_proxies()
            
            if should_remove:
                print(f"   ✓ شرط ۱: تعداد پروکسی‌ها ({initial_count + added_count}) > ۵۰")
                print(f"   ✓ شرط ۲: {len(old_proxies)} پروکسی قدیمی‌تر از ۳ روز")
                print(f"   ⚡ هر دو شرط برقرار است")
                
                removed_count = self.remove_old_proxies_with_conditions()
                if removed_count > 0:
                    print(f"   ✅ {removed_count} پروکسی قدیمی حذف شدند")
                else:
                    print(f"   ℹ️  با وجود شرایط، پروکسی‌ای حذف نشد")
            else:
                print(f"   ⏸️  شرایط حذف برقرار نیست:")
                if (initial_count + added_count) <= 50:
                    print(f"     ✗ تعداد کل ({initial_count + added_count}) ≤ ۵۰")
                if len(old_proxies) == 0:
                    print(f"     ✗ پروکسی قدیمی‌تر از ۳ روز وجود ندارد")
            
            # 5. بررسی حداقل تعداد
            current_count = len(self.config.get('proxies', []))
            if current_count < 50:
                print(f"\n🔧 تکمیل تا حداقل ۵۰ پروکسی:")
                emergency_added = self.ensure_minimum_proxies()
                if emergency_added > 0:
                    print(f"   ✅ {emergency_added} پروکسی اضطراری اضافه شد")
            else:
                print(f"\n✅ تعداد پروکسی‌ها کافی است ({current_count})")
            
            # 6. بررسی تکراری‌ها
            print(f"\n🔍 بررسی نهایی تکراری‌ها:")
            duplicates = self.check_for_duplicates()
            if duplicates:
                print(f"   ⚠️  {len(duplicates)} پروکسی تکراری پیدا شد!")
                for dup in duplicates[:3]:
                    print(f"     • {dup}")
                if len(duplicates) > 3:
                    print(f"     • ... و {len(duplicates) - 3} مورد دیگر")
            else:
                print(f"   ✅ هیچ پروکسی تکراری وجود ندارد")
            
            # 7. ذخیره تغییرات
            print(f"\n💾 ذخیره تغییرات در فایل...")
            if self.save_config():
                print(f"   ✅ تغییرات با موفقیت ذخیره شد")
            else:
                print(f"   ❌ خطا در ذخیره‌سازی")
                return False
            
            # 8. نمایش آمار نهایی
            print(f"\n" + "=" * 70)
            print("📈 گزارش نهایی")
            print("=" * 70)
            
            final_count = len(self.config.get('proxies', []))
            analysis = self.analyze_proxies()
            
            print(f"\n📊 آمار پروکسی‌ها:")
            print(f"   • مجموع: {analysis['total']}")
            print(f"   • امروزی: {analysis['age_stats']['today']}")
            print(f"   • ۱ روزه: {analysis['age_stats']['1_day']}")
            print(f"   • ۲ روزه: {analysis['age_stats']['2_days']}")
            print(f"   • ۳ روزه: {analysis['age_stats']['3_days']}")
            print(f"   • قدیمی: {analysis['age_stats']['older']}")
            
            print(f"\n🌍 توزیع کشورها:")
            for country, count in analysis['country_stats'].items():
                percentage = (count / analysis['total']) * 100
                print(f"   • {country}: {count} ({percentage:.1f}%)")
            
            print(f"\n📅 محدوده زمانی:")
            print(f"   • قدیمی‌ترین: {analysis['oldest_date']}")
            print(f"   • جدیدترین: {analysis['newest_date']}")
            
            print(f"\n📈 تغییرات کلی: {final_count - initial_count:+d} پروکسی")
            
            if final_count >= 50:
                print(f"\n✅ موفقیت: حداقل {final_count} پروکسی فعال موجود است")
            else:
                print(f"\n⚠️  هشدار: فقط {final_count} پروکسی موجود است")
            
            print("=" * 70)
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
    """تابع اصلی اجرا"""
    print("🔧 مدیر پروکسی‌های ایرانی v1.0")
    print("📅 " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    # ایجاد شیء مدیر پروکسی
    manager = ProxyManager()
    
    # اجرای فرآیند
    success = manager.run()
    
    # خروج با کد مناسب
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
