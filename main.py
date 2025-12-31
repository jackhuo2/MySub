import json
import requests
import base64
import yaml

# 数据源列表
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
    # 1. 基础字段提取
    raw_server = item.get('server') or item.get('add')
    raw_port = item.get('port') or item.get('server_port') or item.get('port_num')
    
    # 解析复合型 Server (如 1.2.3.4:5678)
    if raw_server and ':' in str(raw_server) and not raw_port:
        if '[' in str(raw_server):
            parts = str(raw_server).split(']:')
            server = parts[0] + ']'
            port = parts[1] if len(parts) > 1 else ""
        else:
            parts = str(raw_server).rsplit(':', 1)
            server, port = parts[0], parts[1]
    else:
        server, port = raw_server, raw_port

    if not server or not port: return None

    # 2. 协议识别
    p_type = str(item.get('type', '')).lower()
    if not p_type and item.get('auth') and item.get('bandwidth'):
        p_type = 'hysteria2'

    # 3. 辅助字段提取
    server_display = f"[{server}]" if ":" in str(server) and "[" not in str(server) and "," not in str(server) else server
    tls_data = item.get('tls', {})
    if isinstance(tls_data, bool): tls_data = {}
    sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or tls_data.get('sni') or "www.bing.com"
    
    # 节点命名逻辑：协议_IP末段_端口
    tag = p_type.upper()
    addr_brief = str(server).split('.')[-1] if '.' in str(server) else "v6"
    node_name = f"{tag}_{addr_brief}_{port}"

    # 4. 各协议转换逻辑
    # --- Hysteria 2 ---
    if p_type in ['hysteria2', 'hy2']:
        auth = item.get('auth') or item.get('password') or item.get('auth-str')
        return f"hysteria2://{auth}@{server_display}:{port}/?sni={sni}&insecure=1#{node_name}"

    # --- VLESS Reality ---
    elif p_type == 'vless':
        uuid = item.get('uuid') or item.get('id')
        link = f"vless://{uuid}@{server_display}:{port}?encryption=none&security=reality&sni={sni}"
        ropts = item.get('reality-opts', {})
        rbox = tls_data.get('reality', {})
        pbk = ropts.get('public-key') or rbox.get('public_key')
        sid = ropts.get('short-id') or rbox.get('short_id')
        if pbk: link += f"&pbk={pbk}"
        if sid: link += f"&sid={sid}"
        return f"{link}#{node_name}"

    # --- TUIC ---
    elif p_type == 'tuic':
        uuid = item.get('uuid') or item.get('id') or item.get('password')
        # 增加 version=5 以提升客户端兼容性
        return f"tuic://{uuid}@{server_display}:{port}?version=5&sni={sni}&insecure=1&alpn=h3#{node_name}"
    
    # --- Hysteria 1 ---
    elif p_type == 'hysteria':
        auth = item.get('auth') or item.get('auth-str')
        return f"hysteria://{server_display}:{port}/?auth={auth}&sni={sni}&insecure=1#{node_name}"

    # --- Trojan ---
    elif p_type == 'trojan':
        pw = item.get('password')
        return f"trojan://{pw}@{server_display}:{port}?security=tls&sni={sni}#{node_name}"

    return None

def main():
    unique_links = set()
    for url in URL_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            
            # 情况1: Clash YAML 格式
            if 'clash' in url or 'proxies:' in r.text:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict) and 'proxies' in data:
                    for p in data['proxies']:
                        link = parse_to_link(p)
                        if link: unique_links.add(link)
            # 情况2: Sing-box/JSON 格式
            else:
                data = json.loads(r.text)
                if isinstance(data, dict):
                    if 'outbounds' in data:
                        for o in data['outbounds']:
                            link = parse_to_link(o)
                            if link: unique_links.add(link)
                    elif data.get('server') or data.get('add'):
                        link = parse_to_link(data)
                        if link: unique_links.add(link)
        except:
            continue

    if unique_links:
        # 排序并生成最终文本
        final_list = sorted(list(unique_links))
        full_content = "\n".join(final_list)
        
        # 写入明文 nodes.txt
        with open("nodes.txt", "w", encoding="utf-8") as f:
            f.write(full_content)
            
        # 写入 Base64 sub.txt (去除首尾空格防止软件解析失败)
        encoded_content = base64.b64encode(full_content.strip().encode("utf-8")).decode("utf-8")
        with open("sub.txt", "w", encoding="utf-8") as f:
            f.write(encoded_content)
            
        print(f"✅ 抓取成功！共获得 {len(final_list)} 个去重节点。")
    else:
        print("❌ 未发现任何节点。")

if __name__ == "__main__":
    main()
