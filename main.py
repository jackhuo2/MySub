import json, requests, base64, yaml, urllib.parse, warnings
from datetime import datetime, timedelta

# 禁用不必要的安全警告
warnings.filterwarnings("ignore")

# 数据源列表
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/singbox/1/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
]

beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%m%d-%H%M")

def get_node_info(item):
    """
    严格按照 Alvin9999 的 JSON 结构解析节点信息
    """
    try:
        if not isinstance(item, dict): return None
        
        # 1. 提取服务器地址与端口
        # 针对格式: "server": "157.254.223.43:27921,28000-29000"
        raw_server = item.get('server') or item.get('add') or item.get('address')
        if not raw_server: return None
        
        if ':' in str(raw_server):
            parts = str(raw_server).split(':')
            server = parts[0]
            # 端口处理: 取冒号后第一个逗号或横杠前的数字
            port_part = parts[1].split(',')[0].split('-')[0].strip()
        else:
            server = raw_server
            port_part = item.get('port') or item.get('server_port') or item.get('port_num')
        
        if not server or not port_part: return None

        # 2. 提取密码/凭据 (针对 Hysteria2 的 auth 字段)
        secret = item.get('auth') or item.get('auth_str') or item.get('auth-str') or \
                 item.get('password') or item.get('uuid') or item.get('id')
        if not secret: return None

        # 3. 确定协议类型
        p_type = str(item.get('type', '')).lower()
        if 'auth' in item or 'hy2' in p_type or 'hysteria2' in p_type:
            p_type = 'hysteria2'
        elif 'uuid' in item or 'id' in item or 'vless' in p_type:
            p_type = 'vless'
        elif 'tuic' in p_type:
            p_type = 'tuic'
        else:
            return None # 过滤掉 socks5, dns 等无关项

        # 4. 提取 SNI (深度穿透 tls 层级)
        tls_obj = item.get('tls', {})
        if not isinstance(tls_obj, dict): tls_obj = {}
        sni = item.get('servername') or item.get('sni') or \
              tls_obj.get('sni') or tls_obj.get('server_name') or ""
        
        # 5. 生成节点名称
        addr_tag = server.split('.')[-1].replace(']', '')
        name = f"{p_type.upper()}_{addr_tag}_{beijing_time}"
        
        return {
            "name": name, "server": server, "port": int(port_part), 
            "type": p_type, "sni": sni, "secret": secret, "raw": item
        }
    except:
        return None

def main():
    all_extracted_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

    for url in URL_SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            if r.status_code != 200: continue
            
            # 解析内容 (JSON 或 YAML)
            try:
                data = json.loads(r.text)
            except:
                data = yaml.safe_load(r.text)
            
            # 递归搜索包含 server 关键词的字典块
            def find_nodes_recursive(obj):
                if isinstance(obj, dict):
                    if any(k in obj for k in ['server', 'add', 'address']):
                        node = get_node_info(obj)
                        if node: all_extracted_nodes.append(node)
                    for v in obj.values(): find_nodes_recursive(v)
                elif isinstance(obj, list):
                    for i in obj: find_nodes_recursive(i)
            
            find_nodes_recursive(data)
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            continue

    # 按照 IP:端口 进行去重
    unique_nodes = []
    seen_addresses = set()
    for n in all_extracted_nodes:
        addr_key = f"{n['server']}:{n['port']}"
        if addr_key not in seen_addresses:
            unique_nodes.append(n)
            seen_addresses.add(addr_key)

    # 生成各格式订阅文件
    uri_links = []
    clash_proxies = []

    for n in unique_nodes:
        name_enc = urllib.parse.quote(n["name"])
        # 处理 IPv6 地址格式
        srv_display = f"[{n['server']}]" if ":" in str(n['server']) and "[" not in str(n['server']) else n['server']
        
        if n["type"] == "hysteria2":
            sni_part = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"hysteria2://{n['secret']}@{srv_display}:{n['port']}?insecure=1&allowInsecure=1{sni_part}#{name_enc}")
            clash_proxies.append({
                "name": n["name"], "type": "hysteria2", "server": n["server"], "port": n["port"],
                "password": n["secret"], "tls": True, "sni": n["sni"], "skip-cert-verify": True
            })
            
        elif n["type"] == "vless":
            raw = n["raw"]
            tls_info = raw.get('tls', {}) if isinstance(raw.get('tls'), dict) else {}
            ropts = raw.get('reality-opts') or tls_info.get('reality', {})
            pbk = ropts.get('public-key') or ropts.get('public_key', '')
            sid = ropts.get('short-id') or ropts.get('short_id', '')
            sni_part = f"&sni={n['sni']}" if n['sni'] else ""
            uri_links.append(f"vless://{n['secret']}@{srv_display}:{n['port']}?encryption=none&security=reality&pbk={pbk}&sid={sid}&type=tcp{sni_part}#{name_enc}")
            clash_proxies.append({
                "name": n["name"], "type": "vless", "server": n["server"], "port": n["port"],
                "uuid": n["secret"], "network": "tcp", "tls": True, "udp": True, "sni": n["sni"], "skip-cert-verify": True
            })

    # 保存结果
    with open("node.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(uri_links))
    
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(uri_links).encode()).decode())
    
    # 简单的 Clash 配置文件生成
    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [p["name"] for p in clash_proxies] + ["DIRECT"]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 处理完成! 原始节点总数: {len(all_extracted_nodes)}, 去重后有效节点: {len(clash_proxies)}")

if __name__ == "__main__":
    main()
