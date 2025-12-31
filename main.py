import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

# 包含所有可能的 Alvin9999 备份源
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ip/singbox/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
]

beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    try:
        if not isinstance(item, dict): return None
        raw_server = item.get('server') or item.get('add') or item.get('address')
        if not raw_server or str(raw_server).startswith('127.'): return None
        
        server_str = str(raw_server).strip()
        server, port = "", ""

        # 1. 地址识别 (兼容 IPv6)
        if ']:' in server_str: 
            server, port = server_str.split(']:')[0] + ']', server_str.split(']:')[1]
        elif server_str.startswith('[') and ']' in server_str:
            server, port = server_str, (item.get('port') or item.get('server_port'))
        elif server_str.count(':') == 1:
            server, port = server_str.split(':')
        else:
            server, port = server_str, (item.get('port') or item.get('server_port') or item.get('port_num'))

        if port: port = str(port).split(',')[0].split('-')[0].split('/')[0].strip()
        if not server or not port: return None

        # 2. 凭据提取
        secret = item.get('auth') or item.get('auth_str') or item.get('auth-str') or \
                 item.get('password') or item.get('uuid') or item.get('id')
        if not secret: return None

        # 3. 协议识别
        p_type = str(item.get('type', '')).lower()
        if 'auth' in item or 'hy2' in p_type or 'hysteria2' in p_type: p_type = 'hysteria2'
        elif 'uuid' in item or 'vless' in p_type: p_type = 'vless'
        else: p_type = 'hysteria2' if 'auth' in item else 'vless'

        # 4. SNI & Reality 参数
        tls_obj = item.get('tls', {}) if isinstance(item.get('tls'), dict) else {}
        sni = item.get('servername') or item.get('sni') or tls_obj.get('sni') or tls_obj.get('server_name') or ""
        
        ropts = item.get('reality-opts') or tls_obj.get('reality', {})
        pbk = ropts.get('public-key') or ropts.get('public_key', '')
        sid = ropts.get('short-id') or ropts.get('short_id', '')
        
        tag = server.split('.')[-1].replace(']', '') if '.' in server else "v6"
        name = f"{p_type.upper()}_{tag}_{port}_{beijing_time}"
        
        return {"name": name, "server": server, "port": int(port), "type": p_type, "sni": sni, "secret": secret, "pbk": pbk, "sid": sid, "raw_server": server_str}
    except: return None

def main():
    raw_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=12, verify=False)
            if r.status_code != 200: continue
            data = json.loads(r.text) if ('json' in url or '{' in r.text[:5]) else yaml.safe_load(r.text)
            
            def extract_dicts(obj):
                res = []
                if isinstance(obj, dict):
                    res.append(obj)
                    for v in obj.values(): res.extend(extract_dicts(v))
                elif isinstance(obj, list):
                    for i in obj: res.extend(extract_dicts(i))
                return res
            
            for d in extract_dicts(data):
                node = get_node_info(d)
                if node: raw_nodes.append(node)
        except: continue

    # 去重
    unique_nodes = []
    seen = set()
    for n in raw_nodes:
        # Key 包含原始地址字符串，防止 Port Hopping 被误杀
        key = f"{n['type']}_{n['raw_server']}_{n['secret']}"
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    uri_links = []
    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv_uri = f"[{n['server']}]" if (':' in n['server'] and not n['server'].startswith('[')) else n['server']
        
        if n["type"] == "hysteria2":
            sni_p = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"hysteria2://{n['secret']}@{srv_uri}:{n['port']}?insecure=1&allowInsecure=1{sni_p}#{name_enc}")
        elif n["type"] == "vless":
            sni_p = f"&sni={n['sni']}" if n['sni'] else ""
            pbk_p = f"&pbk={n['pbk']}" if n['pbk'] else ""
            sid_p = f"&sid={n['sid']}" if n['sid'] else ""
            uri_links.append(f"vless://{n['secret']}@{srv_uri}:{n['port']}?encryption=none&security=reality&type=tcp{sni_p}{pbk_p}{sid_p}#{name_enc}")

    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(uri_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(uri_links).encode()).decode())
    print(f"✅ 完成! 提取到有效节点总数: {len(uri_links)}")

if __name__ == "__main__":
    main()
