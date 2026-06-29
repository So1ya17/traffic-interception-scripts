"""
mitmproxy addon — подробное логирование всех запросов с флагами ошибок.
Поддерживает HTTP, WebSocket и TCP. Выводит в консоль: URL, статус, время, ошибки.
"""

import time
from datetime import datetime
from mitmproxy import ctx, http, tcp, websocket


class TrafficLogger:
    def __init__(self):
        self.stats = {
            "total": 0,
            "success": 0,
            "redirect": 0,
            "client_error": 0,
            "server_error": 0,
            "failed": 0,
            "timeouts": 0,
            "ws": 0,
            "tcp": 0,
        }
        self.start_time = time.time()

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S")

    def _elapsed(self, flow):
        if flow.request.timestamp_end and flow.request.timestamp_start:
            return flow.request.timestamp_end - flow.request.timestamp_start
        return 0

    def _print_req(self, flow, tag, color_code):
        elapsed = self._elapsed(flow)
        req = flow.request
        resp = flow.response
        status = resp.status_code if resp else 0
        url = req.pretty_url
        method = req.method

        if elapsed > 3.0:
            elapsed_str = f"\033[91m{elapsed:.1f}s SLOW\033[0m"
        elif elapsed > 1.0:
            elapsed_str = f"\033[93m{elapsed:.1f}s\033[0m"
        else:
            elapsed_str = f"{elapsed:.1f}s"

        status_str = f"{status}" if status else "---"

        line = f"  {self._ts()} [{color_code}{tag}\033[0m] {method:7s} {status_str:>3s} {elapsed_str:>15s}  {url}"
        print(line, flush=True)

        if resp and resp.headers:
            ct = resp.headers.get("content-type", "")
            cl = resp.headers.get("content-length", "?")
            print(f"            Content-Type: {ct}  Size: {cl}", flush=True)

    def request(self, flow: http.HTTPFlow):
        self.stats["total"] += 1
        self._print_req(flow, "REQ ", "\033[96m")

    def response(self, flow: http.HTTPFlow):
        status = flow.response.status_code if flow.response else 0
        elapsed = self._elapsed(flow)

        if 200 <= status < 300:
            self.stats["success"] += 1
            tag, color = "OK  ", "\033[92m"
        elif 300 <= status < 400:
            self.stats["redirect"] += 1
            tag, color = "REDR", "\033[93m"
            loc = flow.response.headers.get("location", "")
            if loc:
                print(f"            \033[91m→ Redirect to: {loc}\033[0m", flush=True)
        elif 400 <= status < 500:
            self.stats["client_error"] += 1
            tag, color = "ERR4", "\033[91m"
        elif status >= 500:
            self.stats["server_error"] += 1
            tag, color = "ERR5", "\033[91;1m"
            print(f"            \033[91m!!! SERVER ERROR {status} !!!\033[0m", flush=True)

        if elapsed > 5.0:
            print(f"            \033[91m*** TIMEOUT / VERY SLOW ({elapsed:.1f}s) ***\033[0m", flush=True)
            self.stats["timeouts"] += 1
        elif elapsed > 3.0:
            print(f"            \033[93m*** SLOW ({elapsed:.1f}s) ***\033[0m", flush=True)

        self._print_req(flow, tag, color)

    def error(self, flow: http.HTTPFlow):
        self.stats["failed"] += 1
        err = flow.error
        err_msg = str(err) if err else "unknown error"
        err_code = err.code if err and hasattr(err, "code") else "?"

        url = flow.request.pretty_url
        method = flow.request.method

        print(f"\n  {self._ts()} \033[91;1m[FAIL] {method} {url}\033[0m", flush=True)
        print(f"            \033[91mError code: {err_code}\033[0m", flush=True)
        print(f"            \033[91mMessage:    {err_msg}\033[0m", flush=True)

        msg_lower = err_msg.lower()
        if "timeout" in msg_lower:
            print(f"            \033[91m>>> CONNECTION TIMEOUT — сервер не отвечает <<<\033[0m", flush=True)
        elif "refused" in msg_lower:
            print(f"            \033[91m>>> CONNECTION REFUSED — порт закрыт или сервис не запущен <<<\033[0m", flush=True)
        elif "reset" in msg_lower:
            print(f"            \033[91m>>> CONNECTION RESET — сервер разорвал соединение <<<\033[0m", flush=True)
        elif "ssl" in msg_lower or "tls" in msg_lower:
            print(f"            \033[91m>>> SSL/TLS ERROR — проблема с сертификатом <<<\033[0m", flush=True)
        elif "dns" in msg_lower or "resolve" in msg_lower:
            print(f"            \033[91m>>> DNS ERROR — не удаётся разрешить имя хоста <<<\033[0m", flush=True)

        print(f"            {flow.request.headers}", flush=True)

    def websocket_start(self, flow: websocket.WebSocketFlow):
        self.stats["total"] += 1
        self.stats["ws"] += 1
        client = flow.client_conn
        server = flow.server_conn
        url = flow.request.pretty_url
        print(f"  {self._ts()} [\033[95mWS  START\033[0m] {url}", flush=True)
        print(f"            Client: {client.address[0]}:{client.address[1]}", flush=True)
        if server.address:
            print(f"            Server: {server.address[0]}:{server.address[1]}", flush=True)

    def websocket_message(self, flow: websocket.WebSocketFlow):
        if flow.websocket and flow.websocket.messages:
            last_msg = flow.websocket.messages[-1]
            from mitmproxy.net.http import websocket as ws
            direction = "→" if last_msg.from_client else "←"
            msg_type = "text" if isinstance(last_msg.content, str) else "binary"
            size = len(last_msg.content)
            preview = ""
            if msg_type == "text" and size > 0:
                preview = last_msg.content[:120].replace("\n", "\\n")
                if len(last_msg.content) > 120:
                    preview += "..."
            color = "\033[94m" if last_msg.from_client else "\033[93m"
            print(f"  {self._ts()} [{color}WS  {direction}   \033[0m] {msg_type:6s} {size:>6d} B  {preview}", flush=True)

    def websocket_end(self, flow: websocket.WebSocketFlow):
        url = flow.request.pretty_url
        print(f"  {self._ts()} [\033[95mWS  END  \033[0m] {url}", flush=True)

    def tcp_start(self, flow: tcp.TCPFlow):
        self.stats["total"] += 1
        self.stats["tcp"] += 1
        addr = flow.server_conn.address if flow.server_conn else ("?", "?")
        client = flow.client_conn.address if flow.client_conn else ("?", "?")
        print(f"  {self._ts()} [\033[96mTCP START \033[0m] {client[0]}:{client[1]} → {addr[0]}:{addr[1]}", flush=True)

    def tcp_message(self, flow: tcp.TCPFlow):
        if flow.messages:
            last_msg = flow.messages[-1]
            direction = "→" if last_msg.from_client else "←"
            size = len(last_msg.content)
            preview = ""
            try:
                text = last_msg.content[:120].decode("utf-8", errors="replace")
                preview = text.replace("\n", "\\n")
                if len(last_msg.content) > 120:
                    preview += "..."
            except Exception:
                preview = f"(binary {size} B)"
            color = "\033[94m" if last_msg.from_client else "\033[93m"
            print(f"  {self._ts()} [{color}TCP MSG {direction}   \033[0m] {size:>6d} B  {preview}", flush=True)

    def tcp_error(self, flow: tcp.TCPFlow):
        err = flow.error
        err_msg = str(err) if err else "unknown"
        addr = flow.server_conn.address if flow.server_conn else ("?", "?")
        print(f"  {self._ts()} \033[91;1m[TCP FAIL] {addr[0]}:{addr[1]} — {err_msg}\033[0m", flush=True)

    def tcp_end(self, flow: tcp.TCPFlow):
        addr = flow.server_conn.address if flow.server_conn else ("?", "?")
        elapsed = 0
        if flow.server_conn.timestamp_end and flow.server_conn.timestamp_start:
            elapsed = flow.server_conn.timestamp_end - flow.server_conn.timestamp_start
        print(f"  {self._ts()} [\033[96mTCP END  \033[0m] {addr[0]}:{addr[1]} ({elapsed:.1f}s)", flush=True)

    def done(self):
        elapsed = time.time() - self.start_time
        s = self.stats
        print(f"\n{'=' * 60}", flush=True)
        print(f"  СТАТИСТИКА СЕССИИ ({elapsed:.0f}s)", flush=True)
        print(f"{'=' * 60}", flush=True)
        print(f"  Всего запросов:     {s['total']}", flush=True)
        print(f"  HTTP успешных:      \033[92m{s['success']}\033[0m", flush=True)
        print(f"  HTTP редиректы:     \033[93m{s['redirect']}\033[0m", flush=True)
        print(f"  HTTP 4xx:           \033[91m{s['client_error']}\033[0m", flush=True)
        print(f"  HTTP 5xx:           \033[91;1m{s['server_error']}\033[0m", flush=True)
        print(f"  HTTP failed:        \033[91;1m{s['failed']}\033[0m", flush=True)
        print(f"  HTTP timeouts:      \033[91m{s['timeouts']}\033[0m", flush=True)
        print(f"  WebSocket:          \033[95m{s['ws']}\033[0m", flush=True)
        print(f"  TCP:                \033[96m{s['tcp']}\033[0m", flush=True)
        total_issues = s["failed"] + s["server_error"] + s["timeouts"]
        if total_issues > 0:
            print(f"\n  \033[91;1m!!! Есть проблемы: {s['failed']} fail, {s['server_error']} 5xx, {s['timeouts']} timeout !!!\033[0m", flush=True)
        print(f"{'=' * 60}", flush=True)


addons = [TrafficLogger()]
