import json
import requests
import base64
import yaml  # 用于处理 clash.yaml 格式

# 所有的来源链接
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
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/1/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/2/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/3/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/4/config.yaml",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/clash.meta2/5/config.yaml",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/clash.meta2/6/config.yaml"
]

def parse_json(content):
    """解析传统的 Hysteria2 JSON 格式"""
    data = json.loads(content)
    server = data.get('server')
    auth = data.get('auth')
    sni = data.get('tls', {}).get('sni', 'www.bing.com')
    if server and auth:
        return f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1"
    return None

def parse_yaml(content):
    """解析 Clash YAML 格式中的 Hysteria2 或其他协议节点"""
    data = yaml.safe_load(content)
    nodes = []
    # Clash 配置中的节点通常在 proxies 列表下
    proxies = data.get('proxies', [])
    for p in proxies:
        if p.get('type') == 'hysteria2':
            server = f"{p['server']}:{p['port']}"
            auth = p.get('password', p.get('auth'))
            sni = p.get('sni', 'www.bing.com')
            nodes.append(f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1")
    return nodes

def main():
    unique_nodes = set()
    for url in URL_SOURCES:
        try:
            print(f"正在抓取: {url}")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                if url.endswith('.json'):
                    link = parse_json(resp.text)
                    if link: unique_nodes.add(link)
                elif url.endswith('.yaml'):
                    links = parse_yaml(resp.text)
                    for l in links: unique_nodes.add(l)
        except Exception as e:
            print(f"解析失败 {url}: {e}")

    if unique_nodes:
        final_list = [f"{l}#Node_{i+1}" for i, l in enumerate(unique_nodes)]
        b64_data = base64.b64encode("\n".join(final_list).encode()).decode()
        with open("sub.txt", "w") as f:
            f.write(b64_data)
        print(f"成功提取 {len(final_list)} 个去重后的唯一节点")

if __name__ == "__main__":
    main()
