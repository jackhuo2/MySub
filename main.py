import json
import requests
import base64
import yaml
import re

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
    # 提取 server 和 port
    raw_server = item.get('server') or item.get('add')
    raw_port = item.get('port') or item.get('server_port') or item.get('port_num')
    
    # 针对原生 Hy2 格式的特殊处理：server 包含冒号 (1.2.3.4:1234)
    if raw_server and ':' in str(raw_server) and not raw_port:
        # 如果是 IPv6 且带括号
        if '[' in str(raw_server):
            parts = str(raw_server).split(']:')
            server = parts[0] + ']'
            port = parts[1] if len(parts) > 1 else ""
        else:
            # 普通 IPv4:端口 或 域名:端口
            parts = str(raw_server).rsplit(':', 1)
            server = parts[0]
            port = parts[1]
    else:
        server = raw_server
        port = raw_port

    if not server or not port: return None

    # 确定协议类型
    p_type = str(item.get('type', '')).lower()
    # 如果没有明确 type，但有 auth 和 bandwidth，判定为原生 Hy2
    if not p_type and item.get('auth') and item.get('bandwidth'):
        p_type = 'hysteria2'

    server_display = f"[{server}]" if ":" in str(server) and "[" not in str(server) and "," not in str(server) else server
    tls_data = item.get('tls', {})
    if isinstance(tls_data, bool): tls_data = {}
    sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or tls_data.get('sni') or "www.bing.com"

    # 1. Hysteria 2 逻辑
    if p_type in ['hysteria2', 'hy2']:
        auth = item.get('auth') or item.get('password') or item.get('auth-str')
        return f"hysteria2://{auth}@{server_display}:{port}/?sni={sni}&insecure=1"

    # 2. VLESS 逻辑
    elif p_type == 'vless':
        uuid = item.get('uuid') or item.get('id')
        link = f"vless://{uuid}@{server_display}:{port}?encryption=none&security=reality&sni={sni}"
        ropts = item.get('reality-opts', {})
        rbox = tls_data.get('reality', {})
        pbk = ropts.get('public-key') or rbox.get('public_key')
        sid = ropts.get('short-id') or rbox.get('short_id')
        if pbk: link += f"&pbk={pbk}"
        if sid: link += f"&sid={sid}"
        return link

    # 3. 其他协议 (Trojan, TUIC, Hysteria 1)
    elif p_type == 'trojan':
        pw = item.get('password')
        return f"trojan://{pw}@{server_display}:{port}?security=tls&sni={sni}"
    elif p_type == 'tuic':
        uuid = item.get('uuid') or item.get('id')
        return f"tuic://{uuid}@{server_display}:{port}?sni={sni}&insecure=1&alpn=h3"
    elif p_type == 'hysteria':
        auth = item.get('auth') or item.get('auth-str')
        return f"hysteria://{server_display}:{port}/?auth={auth}&sni={sni}&insecure=1"

    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            
            # YAML 处理
            if 'clash' in url or 'proxies:' in r.text:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        link = parse_to_link(p)
                        if link: unique_links.add(link)
            # JSON 处理
            else:
                data = json.loads(r.text)
                if isinstance(data, dict):
                    if 'outbounds' in data:
                        for o in data['outbounds']:
                            link = parse_to_link(o)
                            if link: unique_links.add(link)
                    # 关键：识别原生单个 Hy2 JSON 结构
                    elif data.get('server'):
                        link = parse_to_link(data)
                        if link: unique_links.add(link)
        except: continue

    if unique_links:
        node_list = sorted(list(unique_links))
        final_list = [f"{link}#Node_{i+1}" for i, link in enumerate(node_list)]
        full_content = "\n".join(final_list)
        
        with open("nodes.txt", "w", encoding="utf-8") as f:
            f.write(full_content)
        with open("sub.txt", "w", encoding="utf-8") as f:
            f.write(base64.b64encode(full_content.encode("utf-8")).decode("utf-8"))
        print(f"✅ 成功提取 {len(final_list)} 个节点，Hy2 应该回来了！")
    else:
        print("❌ 依然没有节点。")

if __name__ == "__main__":
    main()
