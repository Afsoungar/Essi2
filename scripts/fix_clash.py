#!/usr/bin/env python3
"""
اسکریپت اصلاح کانفیگ برای GitHub Actions
"""

import os
import yaml
from datetime import datetime

def create_clash_config():
    """ایجاد کانفیگ کلش از فایل اصلی"""
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, 'output', 'config.yaml')
    output_path = os.path.join(base_dir, 'output', 'clash_config.yaml')
    
    if not os.path.exists(input_path):
        print("❌ فایل کانفیگ اصلی یافت نشد!")
        return
    
    with open(input_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    if not config or 'proxies' not in config:
        print("❌ ساختار فایل نامعتبر است!")
        return
    
    clash_proxies = []
    
    for proxy in config['proxies']:
        clash_proxy = {
            'name': proxy.get('name', f"{proxy['server']}:{proxy['port']}"),
            'type': proxy['type'],
            'server': proxy['server'],
            'port': proxy['port'],
            'udp': True  # 🔥 مهم
        }
        
        if proxy['type'] == 'vmess':
            clash_proxy.update({
                'uuid': proxy.get('uuid', ''),
                'alterId': max(proxy.get('alterId', 0), 4),
                'cipher': proxy.get('cipher', 'auto'),
                'tls': proxy.get('tls', False)
            })
            
            # network و ws-opts
            if proxy.get('network') == 'ws':
                clash_proxy['network'] = 'ws'
                if 'ws-opts' in proxy:
                    clash_proxy['ws-opts'] = proxy['ws-opts']
            
            # sni برای TLS
            if clash_proxy.get('tls', False) and 'sni' not in clash_proxy:
                clash_proxy['sni'] = proxy.get('server')
        
        clash_proxies.append(clash_proxy)
    
    # ساختار کامل کلش
    clash_config = {
        'proxies': clash_proxies,
        'proxy-groups': [
            {
                'name': '🚀 Auto Select',
                'type': 'url-test',
                'proxies': [p['name'] for p in clash_proxies],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            },
            {
                'name': '🌍 Proxy',
                'type': 'select',
                'proxies': ['🚀 Auto Select', 'DIRECT']
            }
        ],
        'rules': [
            'DOMAIN-SUFFIX,google.com,🌍 Proxy',
            'DOMAIN-SUFFIX,youtube.com,🌍 Proxy',
            'DOMAIN-SUFFIX,telegram.org,🌍 Proxy',
            'GEOIP,IR,DIRECT',
            'MATCH,🌍 Proxy'
        ]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, 
                 default_flow_style=False, 
                 allow_unicode=True,
                 indent=2)
    
    print(f"✅ فایل کلش ساخته شد: {output_path}")
    print(f"📊 تعداد پروکسی‌ها: {len(clash_proxies)}")

if __name__ == "__main__":
    create_clash_config()
