"""Safe dependency diagnostics: never return raw subprocess output or credentials."""
import http.client
import json
import os
import socket
from urllib.parse import urlsplit


def temporal_failure(output=''):
    address = os.environ.get('TEMPORAL_ADDRESS', 'localhost:7233')
    try:
        parsed = urlsplit('//' + address)
        host, port = parsed.hostname, parsed.port or 7233
        if not host or parsed.username or parsed.password or parsed.path:
            return 'Temporal 地址配置无效，请检查实例 TEMPORAL_ADDRESS。'
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (ValueError, OSError):
        return 'Temporal 服务名无法解析，请检查实例内部服务地址及 DNS。'
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except OSError:
        return 'Temporal 端口无法连接，请检查服务是否启动、服务端口及内部网络规则。'
    connection = http.client.HTTPConnection(host, port, timeout=4)
    try:
        connection.request('GET', '/healthz')
        response = connection.getresponse()
        body = json.loads(response.read(4096))
        if body.get('service') == 'shannon-temporal':
            if body.get('status') == 'database_unavailable':
                return 'Temporal 数据库不可用，请检查 PostgreSQL 状态及持久化数据库凭据；不要删除数据卷。'
            if body.get('status') == 'temporal_starting':
                return 'Temporal 进程尚未就绪，请检查其启动日志、数据库初始化及容器资源。'
            if response.status == 200 and body.get('status') == 'ready':
                if 'PERMISSION_DENIED' in output.upper() or 'UNAUTHENTICATED' in output.upper():
                    return 'Temporal HTTP 健康检查正常，但 gRPC 鉴权失败，请检查服务鉴权配置。'
                return 'Temporal HTTP 健康检查正常，但 gRPC 连接或 default 命名空间初始化失败，请检查 HTTP/2 转发及 Temporal 日志。'
    except (OSError, ValueError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    return 'Temporal 端口可连接，但健康检查或 gRPC 初始化失败，请检查服务端口是否指向正确容器及其启动日志。'
