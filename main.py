import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

# 禁用安全证书警告
warnings.filterwarnings("ignore")

# 20个精准数据源
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

def main():
    all_proxies = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            
            # 尝试解析 YAML (Clash 格式)
            try:
                data = yaml.safe_load(r.text)
                if isinstance(data, dict) and 'proxies' in data:
                    all_proxies.extend(data['proxies'])
                    continue
            except: pass
            
            # 尝试解析 JSON (Sing-box 格式)
            try:
                data = json.loads(r.text)
                if isinstance(data, dict):
                    # 检查 outbounds 或 proxies
                    nodes = data.get('proxies') or data.get('outbounds') or []
                    if isinstance(nodes, list): all_proxies.extend(nodes)
            except: pass
        except: continue

    if not all_proxies:
        print("❌ 未能获取到任何数据")
        return

    # 节点解析与格式化
    processed_nodes = []
    seen_ips = set()

    for item in all_proxies:
        try:
            server = item.get('server') or item.get('add')
            port = item.get('port') or item.get('server_port')
            if not server or not port: continue
            
            # 简单的地址去重
            addr_key = f"{server}:{port}"
            if addr_key in seen_ips: continue
            seen_ips.add(addr_key)

            p_type = str(item.get('type', '')).lower()
            name = f"{p_type.upper()}_{str(server).split('.')[-1]}_{beijing_time}"
            
            # 统一核心数据
            node_data = {
                "name": name, "server": server, "port": int(port), "type": p_type,
                "uuid": item.get('uuid') or item.get('id') or item.get('password'),
                "sni": item.get('servername') or item.get('sni') or "www.microsoft.com",
                "auth": item.get('auth') or item.get('password') or item.get('auth-str'),
                "raw": item
            }
            processed_nodes.append(node_data)
        except: continue

    # 1. 生成 node.txt
    links = []
    for n in processed_nodes:
        name_enc = urllib.parse.quote(n["name"])
        srv = f"[{n['server']}]" if ":" in str(n['server']) else n['server']
        if n["type"] in ["hysteria2", "hy2"]:
            links.append(f"hysteria2://{n['auth']}@{srv}:{n['port']}?sni={n['sni']}&insecure=1#{name_enc}")
        elif n["type"] == "tuic":
            links.append(f"tuic://{n['uuid']}%3A{n['uuid']}@{srv}:{n['port']}?sni={n['sni']}&alpn=h3&congestion_control=cubic#{name_enc}")
        elif n["type"] == "vless":
            # 尝试获取 Reality 参数
            raw = n["raw"]
            ropts = raw.get('reality-opts') or raw.get('tls', {}).get('reality', {}) if isinstance(raw.get('tls'), dict) else {}
            pbk = ropts.get('public-key') or ropts.get('public_key', '')
            sid = ropts.get('short-id') or ropts.get('short_id', '')
            links.append(f"vless://{n['uuid']}@{srv}:{n['port']}?encryption=none&security=reality&sni={n['sni']}&pbk={pbk}&sid={sid}&type=tcp#{name_enc}")

    with open("node.txt", "w", encoding="utf-8") as f: f.write("\n".join(links))
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(links).encode()).decode())

    # 2. 生成 clash.yaml
    clash_list = []
    for n in processed_nodes:
        p = {"name": n["name"], "server": n["server"], "port": n["port"], "udp": True, "tls": True, "sni": n["sni"], "skip-cert-verify": True}
        if n["type"] in ["hysteria2", "hy2"]: p.update({"type": "hysteria2", "password": n["auth"]})
        elif n["type"] == "tuic": p.update({"type": "tuic", "uuid": n["uuid"], "password": n["uuid"], "alpn": ["h3"], "congestion-controller": "cubic"})
        elif n["type"] == "vless": p.update({"type": "vless", "uuid": n["uuid"], "network": "tcp"})
        else: continue
        clash_list.append(p)

    config = {
        "proxies": clash_list,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [x["name"] for x in clash_list] + ["DIRECT"]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("clash.yaml", "w", encoding="utf-8") as f: yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 完成！去重后节点数: {len(processed_nodes)}")

if __name__ == "__main__":
    main()
