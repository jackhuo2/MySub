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

    server_display = f"[{server}]" if ":" in str(server) and "[" not in str(server) else server
    tls_data = item.get('tls', {})
    if isinstance(tls_data, bool): tls_data = {}
    sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or tls_data.get('sni') or "apple.com"

    # Hysteria 1 & 2
    if p_type == 'hysteria2' or p_type == 'hy2':
        auth = item.get('auth') or item.get('password') or item.get('auth-str') or item.get('auth_str')
        return f"hysteria2://{auth}@{server_display}:{port}/?sni={sni}&insecure=1"
    elif p_type == 'hysteria':
        auth = item.get('auth') or item.get('auth-str') or item.get('auth_str')
        return f"hysteria://{server_display}:{port}/?auth={auth}&sni={sni}&insecure=1"

    # VLESS (含 Reality)
    elif p_type == 'vless':
        uuid = item.get('uuid') or item.get('id')
        net = item.get('network') or item.get('transport', {}).get('type', 'tcp')
        link = f"vless://{uuid}@{server_display}:{port}?encryption=none&security=reality&sni={sni}&type={net}"
        ropts = item.get('reality-opts', {})
        rbox = tls_data.get('reality', {})
        pbk = ropts.get('public-key') or rbox.get('public_key')
        sid = ropts.get('short-id') or rbox.get('short_id')
        if pbk: link += f"&pbk={pbk}"
        if sid: link += f"&sid={sid}"
        return link

    # Trojan / TUIC / VMess
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
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            if '.yaml' in url or 'clash' in url or 'proxies:' in r.text:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict):
                    for p in data.get('proxies', []):
                        link = parse_to_link(p)
                        if link: unique_links.add(link)
            else:
                data = json.loads(r.text)
                if 'outbounds' in data:
                    for o in data['outbounds']:
                        if o.get('type') in ['vless', 'vmess', 'hysteria', 'hysteria2', 'hy2', 'trojan', 'tuic']:
                            link = parse_to_link(o)
                            if link: unique_links.add(link)
                elif data.get('server') or data.get('type'):
                    link = parse_to_link(data)
                    if link: unique_links.add(link)
        except: continue

    if unique_links:
        node_list = sorted(list(unique_links))
        final_list = [f"{link}#Node_{i+1}" for i, link in enumerate(node_list)]
        
        # 强制合并成一个大字符串，每个链接后必须换行
        full_content = "\n".join(final_list)
        
        # 1. 写入明文版
        with open("nodes.txt", "w", encoding="utf-8") as f:
            f.writelines(full_content)
            
        # 2. 写入加密版 (直接对明文版整份内容进行 Base64)
        encoded_content = base64.b64encode(full_content.encode("utf-8")).decode("utf-8")
        with open("sub.txt", "w", encoding="utf-8") as f:
            f.write(encoded_content)
            
        print(f"✅ 成功！sub.txt 和 nodes.txt 现在均包含 {len(final_list)} 个节点")
    else:
        print("❌ 未抓取到有效节点")

if __name__ == "__main__":
    main()
