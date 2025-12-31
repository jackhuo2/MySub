import json
import requests
import base64
import yaml

URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/6/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ip/singbox/2/config.json"
]

def parse_hy2_raw(data):
    server = data.get('server')
    auth = data.get('auth') or data.get('password')
    sni = data.get('tls', {}).get('sni') or data.get('sni', 'www.bing.com')
    if server and auth:
        return f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1"
    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            print(f"抓取中: {url}")
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            
            # 情况 1: YAML (Clash)
            if url.endswith('.yaml'):
                data = yaml.safe_load(r.text)
                for p in data.get('proxies', []):
                    if p.get('type') == 'hysteria2':
                        link = parse_hy2_raw(p)
                        if link: unique_links.add(link)
            
            # 情况 2: JSON (Sing-box 或 原始 Hy2)
            else:
                data = json.loads(r.text)
                # 检查是否是 Sing-box 格式
                if 'outbounds' in data:
                    for o in data['outbounds']:
                        if o.get('type') == 'hysteria2':
                            link = parse_hy2_raw(o)
                            if link: unique_links.add(link)
                # 检查是否是 原始 Hy2 格式
                elif data.get('server'):
                    link = parse_hy2_raw(data)
                    if link: unique_links.add(link)
                    
        except Exception as e:
            print(f"解析错误 {url}: {e}")

    if unique_links:
        final_list = [f"{l}#Node_{i+1}" for i, l in enumerate(sorted(unique_links))]
        output = base64.b64encode("\n".join(final_list).encode()).decode()
        with open("sub.txt", "w") as f:
            f.write(output)
        print(f"成功导出 {len(final_list)} 个唯一节点")

if __name__ == "__main__":
    main()
