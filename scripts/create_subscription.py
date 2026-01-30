#!/usr/bin/env python3
"""
ایجاد لینک ساب‌کریپشن برای کلش
"""

import os
import base64
import yaml

def create_subscription():
    """ایجاد لینک ساب‌کریپشن"""
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    clash_path = os.path.join(base_dir, 'output', 'clash_config.yaml')
    
    if not os.path.exists(clash_path):
        print("❌ فایل کلش یافت نشد!")
        return
    
    with open(clash_path, 'r', encoding='utf-8') as f:
        config = f.read()
    
    # encode به base64
    encoded = base64.b64encode(config.encode()).decode()
    
    # ذخیره به عنوان subscription.txt
    sub_path = os.path.join(base_dir, 'output', 'subscription.txt')
    with open(sub_path, 'w') as f:
        f.write(encoded)
    
    print(f"✅ لینک ساب‌کریپشن ساخته شد: {sub_path}")
    
    # همچنین برای raw.githubusercontent.com
    repo_name = os.environ.get('GITHUB_REPOSITORY', 'your-username/your-repo')
    raw_url = f"https://raw.githubusercontent.com/{repo_name}/main/output/subscription.txt"
    
    print(f"\n🔗 لینک مستقیم برای کلش:")
    print(raw_url)
    
    # ذخیره URL
    url_path = os.path.join(base_dir, 'output', 'subscription_url.txt')
    with open(url_path, 'w') as f:
        f.write(raw_url)

if __name__ == "__main__":
    create_subscription()
