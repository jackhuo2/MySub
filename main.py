import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

# 忽略 SSL 警告
warnings.filterwarnings("ignore")

# 数据源列表 (保持原样)
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/1/config.yaml"
]

beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    """超级兼容解析器"""
    try:
        if not isinstance(item, dict): return None
        server = item.get('server') or item.get('add') or item.get('address')
        port = item.get('port') or item.get('server_port') or item.get('port_num')
        
        if server and ':' in str(server) and not port:
            parts = str(server).rsplit(':', 1)
            server, port = parts[0], parts[1]
            
        if not server or not port: return None

        p_type = str(item.get('type', '')).lower()
        if not p_type:
            if 'auth' in item or 'password' in item: p_type = 'hysteria2'
            elif 'uuid' in item: p_type = 'vless'
            else: p_type = 'proxy'

        tls_data = item.get('tls', {})
        if isinstance(tls_data, bool): tls_data = {}
        sni = item.get('servername') or item.get('sni') or tls_data.get('server_name') or "www.microsoft.com"
        
        addr_tag = str(server).split('.')[-1] if '.' in str(server) else "v6"
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port), "type": p_type,
            "sni": sni, "uuid": item.get('uuid') or item.get('id') or item.get('password'),
            "auth": item.get('auth') or item.get('password') or item.get('auth-str'),
            "item": item, "tls_data": tls_data
        }
    except: return None

def main():
    nodes_data = []
    # 模拟真实浏览器请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    for url in URL_SOURCES:
        try:
            # 增加 verify=False 忽略证书错误
            r = requests.get(url, headers=headers, timeout=20, verify=False)
            if r.status_code != 200: continue
            
            # 暴力尝试解析
            try:
                content = yaml.safe_load(r.text)
            except:
                content = json.loads(r.text)
            
            if not content: continue

            # 深度搜索：寻找任何包含 'server' 或 'add' 的字典
            def find_nodes(obj):
                if isinstance(obj, dict):
                    if (obj.get('server') or obj.get('add')):
                        info = get_node_info(obj)
                        if info: nodes_data.append(info)
                    for v in obj.values():
                        find_nodes(v)
                elif isinstance(obj, list):
                    for i in obj:
                        find_nodes(i)

            find_nodes(content)
        except Exception as e:
            print(f"解析 {url} 失败: {e}")

    if not nodes_data:
        print("❌ 警告：未发现节点，请检查网络或源地址！")
        return

    # --- 生成 URI (node.txt) ---
    links = []
    for info in nodes_data:
        name_enc = urllib.parse.quote(info["name"])
        srv = f"[{info['server']}]" if ":" in str(info['server']) else info['server']
        if info["type"] in ["tuic"]:
            links.append(f"tuic://{info['uuid']}%3A{info['uuid']}@{srv}:{info['port']}?sni={info['sni']}&alpn=h3&insecure=1&allowInsecure=1&congestion_control=cubic#{name_enc}")
        elif info["type"] in ["hysteria2", "hy2"]:
            links.append(f"hysteria2://{info['auth']}@{srv}:{info['port']}?sni={info['sni']}&insecure=1&allowInsecure=1#{name_enc}")
        elif info["type"] == "vless":
            r = info["item"].get('reality-opts') or info["tls_data"].get('reality', {})
            pbk = r.get('public-key') or r.get('public_key', '')
            sid = r.get('short-id') or r.get('short_id', '')
            links.append(f"vless://{info['uuid']}@{srv}:{info['port']}?encryption=none&security=reality&sni={info['sni']}&pbk={pbk}&sid={sid}&type=tcp&headerType=none#{name_enc}")

    unique_links = sorted(list(set(links)))
    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(unique_links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(unique_links).encode()).decode())

    # --- 生成 Clash ---
    clash_proxies = []
    seen = set()
    for n in nodes_data:
        # 去重并构建 Clash 节点
        key = f"{n['server']}:{n['port']}"
        if key in seen: continue
        seen.add(key)

        p = {"name": n["name"], "server": n["server"], "port": n["port"], "udp": True, "tls": True, "sni": n["sni"], "skip-cert-verify": True}
        if n["type"] in ["hysteria2", "hy2"]:
            p.update({"type": "hysteria2", "password": n["auth"]})
        elif n["type"] == "tuic":
            p.update({"type": "tuic", "uuid": n["uuid"], "password": n["uuid"], "alpn": ["h3"], "congestion-controller": "cubic"})
        elif n["type"] == "vless":
            p.update({"type": "vless", "uuid": n["uuid"], "network": "tcp"})
        else: continue
        clash_proxies.append(p)

    config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [p["name"] for p in clash_proxies] + ["DIRECT"]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("clash.yaml", "w", encoding="utf-8") as f: yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"成功完成！捕获节点总数: {len(clash_proxies)}")

if __name__ == "__main__":
    main()
