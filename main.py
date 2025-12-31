import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

warnings.filterwarnings("ignore")

URL_SOURCES = [
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

beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    try:
        if not isinstance(item, dict): return None
        # 提取核心地址和端口
        server = item.get('server') or item.get('add') or item.get('address')
        port = item.get('port') or item.get('server_port') or item.get('port_num')
        if not server or not port or str(server).startswith('127.'): return None

        # 1. 深度识别 Hysteria2
        p_type = str(item.get('type', '')).lower()
        # 如果类型明确是 hy2 或者包含 auth/password 但没有 uuid，默认为 hy2
        is_hy2 = p_type in ['hy2', 'hysteria2'] or ('auth' in item and 'uuid' not in item)
        
        if is_hy2:
            p_type = 'hysteria2'
            # 尝试所有可能的密码字段
            secret = item.get('auth') or item.get('password') or item.get('auth_str') or item.get('auth-str')
        else:
            secret = item.get('uuid') or item.get('id') or item.get('password')

        if not secret: return None # 没有凭据的节点无效

        # 2. SNI 提取
        tls_obj = item.get('tls', {})
        if not isinstance(tls_obj, dict): tls_obj = {}
        sni = item.get('servername') or item.get('sni') or tls_obj.get('server_name') or tls_obj.get('sni') or "www.microsoft.com"
        
        addr_tag = str(server).split('.')[-1] if '.' in str(server) else "node"
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "secret": secret, "raw": item
        }
    except: return None

def main():
    nodes_list = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            
            try:
                data = yaml.safe_load(r.text)
            except:
                data = json.loads(r.text)
            
            # 递归搜索
            def find_dict_with_server(obj):
                if isinstance(obj, dict):
                    if (obj.get('server') or obj.get('add')) and (obj.get('port') or obj.get('server_port')):
                        node = get_node_info(obj)
                        if node: nodes_list.append(node)
                    for v in obj.values(): find_dict_with_server(v)
                elif isinstance(obj, list):
                    for i in obj: find_dict_with_server(i)

            find_dict_with_server(data)
        except: continue

    if not nodes_list: return

    # 去重
    unique_nodes = []
    seen = set()
    for n in nodes_list:
        key = f"{n['server']}:{n['port']}"
        if key not in seen:
            unique_nodes.append(n)
            seen.add(key)

    # 生成文件
    links = []
    clash_proxies = []

    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv = f"[{n['server']}]" if ":" in str(n['server']) else n['server']
        
        # 链接与配置生成
        if n["type"] == "hysteria2":
            links.append(f"hysteria2://{n['secret']}@{srv}:{n['port']}?sni={n['sni']}&insecure=1#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "hysteria2", "server": n["server"], "port": n["port"], "password": n["secret"], "tls": True, "sni": n["sni"], "skip-cert-verify": True, "udp": True})
        
        elif n["type"] == "tuic":
            links.append(f"tuic://{n['secret']}%3A{n['secret']}@{srv}:{n['port']}?sni={n['sni']}&alpn=h3&congestion_control=cubic#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "tuic", "server": n["server"], "port": n["port"], "uuid": n["secret"], "password": n["secret"], "alpn": ["h3"], "tls": True, "sni": n["sni"], "skip-cert-verify": True, "udp": True})
        
        elif n["type"] == "vless":
            raw = n["raw"]
            ro = raw.get('reality-opts') or raw.get('tls', {}).get('reality', {}) if isinstance(raw.get('tls'), dict) else {}
            pbk = ro.get('public-key') or ro.get('public_key', '')
            sid = ro.get('short-id') or ro.get('short_id', '')
            links.append(f"vless://{n['secret']}@{srv}:{n['port']}?encryption=none&security=reality&sni={n['sni']}&pbk={pbk}&sid={sid}&type=tcp#{name_enc}")
            clash_proxies.append({"name": n["name"], "type": "vless", "server": n["server"], "port": n["port"], "uuid": n["secret"], "network": "tcp", "tls": True, "udp": True, "sni": n["sni"], "skip-cert-verify": True})

    # 写入文件
    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(links).encode()).decode())
    
    conf = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [x["name"] for x in clash_proxies] + ["DIRECT"]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 成功！总节点: {len(clash_proxies)} (包含 HY2/VLESS/TUIC)")

if __name__ == "__main__":
    main()
