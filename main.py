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

def parse_to_link(item):
    p_type = str(item.get('type', '')).lower()
    server = item.get('server') or item.get('add')
    port = item.get('port') or item.get('server_port') or item.get('port_num')
    if not server or not port: return None

    # IPv6 处理
    server_display = f"[{server}]" if ":" in str(server) and "[" not in str(server) else server
    
    # SNI 提取 (Clash 常用 servername，Singbox 常用 server_name)
    tls_data = item.get('tls', {})
    if isinstance(tls_data, bool): tls_data = {} # 处理有的配置里 tls: true
    sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or tls_data.get('sni') or "apple.com"

    # 1. Hysteria 1 & 2
    if p_type == 'hysteria2':
        auth = item.get('auth') or item.get('password') or item.get('auth-str')
        return f"hysteria2://{auth}@{server_display}:{port}/?sni={sni}&insecure=1"
    elif p_type == 'hysteria':
        auth = item.get('auth') or item.get('auth-str')
        return f"hysteria://{server_display}:{port}/?auth={auth}&sni={sni}&insecure=1"

    # 2. VLESS (含 Reality 逻辑)
    elif p_type == 'vless':
        uuid = item.get('uuid') or item.get('id')
        net = item.get('network') or item.get('transport', {}).get('type', 'tcp')
        link = f"vless://{uuid}@{server_display}:{port}?encryption=none&security=reality&sni={sni}&type={net}"
        # Reality 处理 (Clash 风格)
        ropts = item.get('reality-opts', {})
        # Reality 处理 (Singbox 风格)
        rbox = tls_data.get('reality', {})
        pbk = ropts.get('public-key') or rbox.get('public_key')
        sid = ropts.get('short-id') or rbox.get('short_id')
        if pbk: link += f"&pbk={pbk}"
        if sid: link += f"&sid={sid}"
        return link

    # 3. Trojan / TUIC / VMess
    elif p_type == 'trojan':
        pw = item.get('password')
        return f"trojan://{pw}@{server_display}:{port}?security=tls&sni={sni}"
    elif p_type == 'tuic':
        uuid = item.get('uuid') or item.get('id') or item.get('password')
        return f"tuic://{uuid}@{server_display}:{port}?sni={sni}&insecure=1&alpn=h3"
    elif p_type == 'vmess':
        vid = item.get('uuid') or item.get('id')
        v2_config = {"v": "2", "ps": "Node", "add": server, "port": port, "id": vid, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "tls": "tls", "sni": sni}
        return f"vmess://{base64.b64encode(json.dumps(v2_config).encode()).decode()}"

    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            print(f"正在抓取: {url}")
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            
            # 判断是否是 YAML/Clash
            if '.yaml' in url or 'clash' in url or 'proxies:' in r.text:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict):
                    for p in data.get('proxies', []):
                        link = parse_to_link(p)
                        if link: unique_links.add(link)
            # 判断是否是 JSON/Sing-box
            else:
                data = json.loads(r.text)
                if 'outbounds' in data:
                    for o in data['outbounds']:
                        if o.get('type') in ['vless', 'vmess', 'hysteria', 'hysteria2', 'trojan', 'tuic']:
                            link = parse_to_link(o)
                            if link: unique_links.add(link)
                elif data.get('server') or data.get('type'):
                    link = parse_to_link(data)
                    if link: unique_links.add(link)
        except Exception as e:
            print(f"解析失败: {e}")

    if unique_links:
        node_list = sorted(list(unique_links))
        final_list = [f"{link}#ChromeGo_{i+1}" for i, link in enumerate(node_list)]
        with open("sub.txt", "w") as f:
            f.write(base64.b64encode("\n".join(final_list).encode()).decode())
        with open("nodes.txt", "w") as f:
            f.write("\n".join(final_list))
        print(f"✅ 抓取完成！去重后共获得 {len(final_list)} 个节点")
    else:
        print("❌ 未发现任何有效节点")

if __name__ == "__main__":
    main()
