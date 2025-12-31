import json
import requests
import base64

# 你提供的 8 个 Hysteria2 节点链接
URL_SOURCES = [
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/hysteria2/4/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/1/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/2/config.json",
    "https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/hysteria2/3/config.json",
    "https://fastly.jsdelivr.net/gh/Alvin9999/PAC@latest/backup/img/1/2/ipp/hysteria2/4/config.json"
]

def main():
    unique_nodes = {} # 使用字典，以 server 为 key 进行去重

    for url in URL_SOURCES:
        try:
            print(f"抓取中: {url}")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                config = resp.json()
                server = config.get('server')
                auth = config.get('auth')
                sni = config.get('tls', {}).get('sni', 'www.bing.com')
                
                if server and auth:
                    # 只要 server 不同，就认为是新节点
                    link = f"hysteria2://{auth}@{server}/?sni={sni}&insecure=1"
                    unique_nodes[server] = link
                    print(f"发现有效节点: {server}")
        except Exception as e:
            print(f"请求失败 {url}: {e}")
    
    node_list = list(unique_nodes.values())
    if node_list:
        # 给节点排个序并加标签
        final_list = [f"{link}#Node_{i+1}" for i, link in enumerate(node_list)]
        combined_str = "\n".join(final_list)
        b64_sub = base64.b64encode(combined_str.encode('utf-8')).decode('utf-8')
        
        with open("sub.txt", "w") as f:
            f.write(b64_sub)
        print(f"成功！去重后共获得 {len(node_list)} 个节点。")
    else:
        print("警告：未抓取到任何节点。")

if __name__ == "__main__":
    main()
