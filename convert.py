import os
import base64
import requests
import json
import socket
import urllib.parse
from dotenv import load_dotenv

load_dotenv()  # 自动加载 .env 文件

def fetch_subscription(url):
    """
    从订阅链接获取内容
    """
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"无法获取订阅内容: {e}")
        return None

def decode_base64(encoded_data):
    """
    解码 Base64 数据，自动修复填充问题
    """
    try:
        # 修复 Base64 填充问题
        missing_padding = len(encoded_data) % 4
        if missing_padding != 0:
            encoded_data += "=" * (4 - missing_padding)
        decoded_data = base64.b64decode(encoded_data).decode("utf-8")
        return decoded_data
    except Exception as e:
        print(f"Base64 解码失败: {e}")
        return None

def parse_subscription(data):
    exclude_keywords = ["流量", "套餐", "官网", "官網", "Q群", "国家"]
    nodes = []
    for line in data.splitlines():
        line = line.strip()
        # print(f"订阅内容行: {line}")  # 调试输出
        if line.startswith("ss://"):
            node = parse_shadowsocks(line)
        elif line.startswith("vmess://"):
            node = parse_vmess(line)
        elif line.startswith("vless://"):
            node = parse_vless(line)
        elif line.startswith("trojan://"):
            node = parse_trojan(line)
        else:
            node = None
        if node and not any(kw in node["tag"] for kw in exclude_keywords):
            nodes.append(node)
    return nodes

def parse_shadowsocks(link):
    """
    解析 Shadowsocks 链接
    """
    try:
        # ss://{base64(method:password)}@{server}:{port}#{tag}
        if "#" in link:
            info, tag = link[5:].split("#", 1)
        else:
            info = link[5:]
            tag = "Unnamed"

        if '@' not in info:
            print(f"解析 Shadowsocks 链接失败: 格式错误，缺少 '@'")
            return None

        base64_part, server_port = info.split("@", 1)
        missing_padding = len(base64_part) % 4
        if missing_padding != 0:
            base64_part += "=" * (4 - missing_padding)
        try:
            method_password = base64.b64decode(base64_part).decode("utf-8")
        except Exception as e:
            print(f"解析 Shadowsocks 链接失败: base64 解码错误: {e}")
            return None

        if ':' not in method_password or ':' not in server_port:
            print(f"解析 Shadowsocks 链接失败: 格式错误，缺少 ':'")
            return None

        method, password = method_password.split(":", 1)
        server, port = server_port.split(":", 1)

        # 域名解析为IP
        try:
            ip_server = socket.gethostbyname(server)
        except Exception:
            ip_server = server  # 如果解析失败则保留原域名

        # 对 tag 进行 URL 解码
        tag = urllib.parse.unquote(tag)
        # 去除空格、｜、|、流媒体
        tag = tag.replace(" ", "").replace("｜", "").replace("|", "").replace("流媒体", "")

        return {
            "tag": tag,
            "type": "shadowsocks",
            "server": ip_server,
            "server_port": int(port),
            "method": method,
            "password": password
        }
    except Exception as e:
        print(f"解析 Shadowsocks 链接失败: {e}")
        return None

def parse_vmess(link):
    """
    解析 vmess 链接为 singbox 格式，支持 base64(json) 和 URI 格式
    """
    try:
        b64 = link[8:]
        # 判断是否为 base64(json) 格式
        try:
            missing_padding = len(b64) % 4
            if missing_padding != 0:
                b64 += "=" * (4 - missing_padding)
            decoded = base64.b64decode(b64).decode("utf-8")
            vmess_json = json.loads(decoded)
            tag = vmess_json.get("ps", vmess_json.get("add", "vmess"))
            tag = tag.replace(" ", "").replace("｜", "").replace("|", "").replace("流媒体", "")
            return {
                "tag": tag,
                "type": "vmess",
                "server": vmess_json["add"],
                "server_port": int(vmess_json["port"]),
                "uuid": vmess_json["id"],
                "alterId": int(vmess_json.get("aid", 0)),
                "cipher": vmess_json.get("scy", vmess_json.get("encryption", "auto")),
                "network": vmess_json.get("net", "tcp"),
                "ws-opts": {
                    "path": vmess_json.get("path", ""),
                    "headers": {
                        "Host": vmess_json.get("host", "")
                    }
                }
            }
        except Exception:
            # URI 格式解析
            main, params = b64.split("?", 1)
            uuid_server, server_port = main.split("@")
            server, port = server_port.split(":")
            params_dict = dict(urllib.parse.parse_qsl(params))
            tag = server
            tag = tag.replace(" ", "").replace("｜", "").replace("|", "").replace("流媒体", "")
            return {
                "tag": tag,
                "type": "vmess",
                "server": server,
                "server_port": int(port),
                "uuid": uuid_server,
                "alterId": 0,
                "cipher": params_dict.get("encryption", "auto"),
                "network": params_dict.get("type", "tcp"),
                "ws-opts": {
                    "path": params_dict.get("path", ""),
                    "headers": {
                        "Host": params_dict.get("host", "")
                    }
                }
            }
    except Exception as e:
        print(f"解析 vmess 链接失败: {e}")
        return None

def parse_vless(link):
    """
    解析 vless 链接为 singbox 格式（仅基础字段，按你的需求可扩展）
    """
    try:
        # vless://uuid@server:port?...#tag
        url = link[8:]
        if "#" in url:
            url, tag = url.split("#", 1)
        else:
            tag = "Unnamed"
        tag = urllib.parse.unquote(tag)
        tag = tag.replace(" ", "").replace("｜", "").replace("|", "").replace("流媒体", "")

        main, params = url.split("?", 1)
        uuid_server, server_port = main.split("@")
        server, port = server_port.split(":")
        params_dict = dict(urllib.parse.parse_qsl(params))

        # 域名解析为IP
        try:
            ip_server = socket.gethostbyname(server)
        except Exception:
            ip_server = server

        return {
            "tag": tag,
            "type": "vless",
            "server": ip_server,
            "server_port": int(port),
            "uuid": uuid_server,
            "flow": params_dict.get("flow", ""),
            "security": params_dict.get("security", ""),
            "network": params_dict.get("type", "tcp"),
            "tls": params_dict.get("security", "") == "tls",
            "sni": params_dict.get("sni", ""),
            "fp": params_dict.get("fp", ""),
            "ws-opts": {
                "path": params_dict.get("path", ""),
                "headers": {
                    "Host": params_dict.get("host", "")
                }
            }
        }
    except Exception as e:
        print(f"解析 vless 链接失败: {e}")
        return None

def parse_trojan(link):
    """
    解析 trojan 链接为 singbox 格式（仅基础字段，按你的需求可扩展）
    """
    try:
        # trojan://password@server:port?...#tag
        url = link[9:]
        if "#" in url:
            url, tag = url.split("#", 1)
        else:
            tag = "Unnamed"
        tag = urllib.parse.unquote(tag)
        tag = tag.replace(" ", "").replace("｜", "").replace("|", "").replace("流媒体", "")

        main, params = url.split("?", 1)
        password_server, server_port = main.split("@")
        server, port = server_port.split(":")
        params_dict = dict(urllib.parse.parse_qsl(params))

        # 域名解析为IP
        try:
            ip_server = socket.gethostbyname(server)
        except Exception:
            ip_server = server

        return {
            "tag": tag,
            "type": "trojan",
            "server": ip_server,
            "server_port": int(port),
            "password": password_server,
            "sni": params_dict.get("sni", ""),
            "peer": params_dict.get("peer", ""),
            "network": params_dict.get("type", "tcp"),
            "allow_insecure": params_dict.get("allowInsecure", "0") == "1"
        }
    except Exception as e:
        print(f"解析 trojan 链接失败: {e}")
        return None

# 修改 replace_outbounds 支持直接传 nodes 列表
def replace_outbounds(config_path, nodes, output_path):
    with open(config_path, "r") as f:
        config = json.load(f)

    tag_to_node = {node["tag"]: node for node in nodes if "tag" in node}

    outbounds = config.get("outbounds", [])
    for i, outbound in enumerate(outbounds):
        tag = outbound.get("tag")
        if tag and tag in tag_to_node:
            outbounds[i] = tag_to_node[tag]

    config["outbounds"] = outbounds
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"已替换并保存到 {output_path}")

def main():

    subscription_url = os.getenv("SUBSCRIPTION_WENZI")
    if not subscription_url:
        print("请在 .env 文件中设置订阅链接")
        exit(1)

    # 获取订阅内容
    subscription_data = fetch_subscription(subscription_url)
    if not subscription_data:
        return
    
    # print(subscription_data[:200])  # 打印前200字符，确认格式

    # 如果不是以 ss:// 或 vmess:// 开头，尝试整体 base64 解码
    if not (subscription_data.startswith("ss://") or subscription_data.startswith("vmess://")):
        decoded = decode_base64(subscription_data)
        if decoded:
            subscription_data = decoded

    nodes = parse_subscription(subscription_data)
    if not nodes:
        print("未找到有效的节点信息")
        return

    # # 保存节点信息到单独文件
    # with open("nodes_only.json", "w") as f:
    #     json.dump(nodes, f, indent=2, ensure_ascii=False)
    # print("节点信息已保存到 nodes_only.json")

    # 直接替换 config.json 的 outbounds
    replace_outbounds(os.getenv("SINGBOX_CONFIG"), nodes, os.getenv("SINGBOX_CONFIG"))

if __name__ == "__main__":
    main()
