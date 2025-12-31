import json
import requests
import base64
import yaml

# 你的所有来源链接
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

def parse_to_link(item):
    p_type = item.get('type', '').lower()
    server = item.get('server')
    port = item.get('port')
    if not server or not port: return None

    # 1. Hysteria2
    if p_type == 'hysteria2':
        auth = item.get('auth') or item.get('password')
        sni = item.get('tls', {}).get('sni') or item.get('sni', 'www.bing.com')
        return f"hysteria2://{auth}@{server}:{port}/?sni={sni}&insecure=1"

    # 2. VLESS
    elif p_type == 'vless':
        uuid = item.get('uuid')
        sni = item.get('tls', {}).get('sni') or item.get('sni', '')
        return f"vless://{uuid}@{server}:{port}?encryption=none&security=tls&sni={sni}&type=tcp"

    # 3. Trojan
    elif p_type == 'trojan':
        pw = item.get('password')
        sni = item.get('tls', {}).get('sni') or item.get('sni', '')
        return f"trojan://{pw}@{server}:{port}?security=tls&sni={sni}"

    # 4. TUIC
    elif p_type == 'tuic':
        uuid = item.get('uuid')
        pw = item.get('password')
        sni = item.get('tls', {}).get('sni') or item.get('sni', '')
        return f"tuic://{uuid}:{pw}@{server}:{port}?sni={sni}&insecure=1&alpn=h3"

    # 5. VMess
    elif p_type == 'vmess':
        v2_config = {
            "v": "2", "ps": "VMess_Node", "add": server, "port": port,
            "id": item.get('uuid') or item.get('id'), "aid": "0", "scy": "auto",
            "net": "tcp", "type": "none", "host": "", "path": "", "tls": ""
        }
        v2_json = json.dumps(v2_config)
        return f"vmess://{base64.b64encode(v2_json.encode()).decode()}"

    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            
            if url.endswith('.yaml'):
                data = yaml.safe_load(r.text)
                for p in data.get('proxies', []):
                    link = parse_to_link(p)
                    if link: unique_links.add(link)
            else:
                data = json.loads(r.text)
                if 'outbounds' in data: # Sing-box
                    for o in data['outbounds']:
                        link = parse_to_link(o)
                        if link: unique_links.add(link)
                elif data.get('server'): # Raw JSON
                    link = parse_to_link(data)
                    if link: unique_links.add(link)
        except: continue

    if unique_links:
        node_list = sorted(list(unique_links))
        final_list = [f"{link}#Node_{i+1}" for i, link in enumerate(node_list)]
        output = base64.b64encode("\n".join(final_list).encode()).decode()
        with open("sub.txt", "w") as f:
            f.write(output)
        print(f"✅ 成功抓取全协议共 {len(final_list)} 个节点")

if __name__ == "__main__":
    main()
