import asyncio
import json
import time
from collections import deque
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

import tls_demo

app = FastAPI(title="HTTP Traffic Monitor")

# DEMO ONLY: thay "*" bằng origin của frontend khi triển khai thực tế.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Lưu tối đa 200 sự kiện gần nhất trong RAM.
event_history = deque(maxlen=200)
connected_clients: set[WebSocket] = set()


def make_event(event_type: str, **data):
    return {
        "id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        **data,
    }


async def publish_event(event: dict):
    """Lưu sự kiện và phát cho các dashboard đang kết nối."""
    event_history.append(event)

    if not connected_clients:
        return

    results = await asyncio.gather(
        *[
            client.send_json(event)
            for client in list(connected_clients)
        ],
        return_exceptions=True,
    )

    for client, result in zip(list(connected_clients), results):
        if isinstance(result, Exception):
            connected_clients.discard(client)


def get_tls_info(request) -> dict:
    """Lấy thông tin TLS ở mức best-effort (hướng B).

    Khi chạy sau reverse-proxy (Botkeep hosting), TLS đã được
    terminate ở proxy nên scope thường không còn ssl_object.
    Ta vẫn ghi scheme / forwarded-proto để dashboard phân biệt
    HTTP plain vs HTTPS và giải thích cho người xem demo.
    """
    scope = request.scope
    headers = request.headers
    scheme = scope.get("scheme", "?")
    fwd_proto = headers.get("x-forwarded-proto")
    tls_version = scope.get("tls_version") or scope.get("ssl_version")
    cipher = scope.get("cipher") or scope.get("ssl_cipher")
    sni = scope.get("servername") or scope.get("sni")
    terminated_at_proxy = tls_version is None and fwd_proto == "https"
    return {
        "scheme": scheme,
        "forwarded_proto": fwd_proto,
        "tls_version": tls_version or ("https (terminated at proxy)" if terminated_at_proxy else None),
        "cipher": cipher,
        "sni": sni or headers.get("host"),
        "terminated_at_proxy": terminated_at_proxy,
        "user_agent": (headers.get("user-agent") or "")[:120] or None,
    }


class TrafficMonitorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Không đưa request giám sát vào log để tránh dashboard tự
        # tạo ra một lượng sự kiện vô hạn.
        if request.url.path.startswith("/ws/"):
            return await call_next(request)

        request_id = str(uuid4())
        started = time.perf_counter()

        client_host = (
            request.client.host if request.client else "unknown"
        )
        client_port = (
            request.client.port if request.client else None
        )

        # Chỉ ghi metadata, không ghi query string, cookie,
        # Authorization hoặc request body.
        tls = get_tls_info(request)
        await publish_event(make_event(
            "request_received",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            http_version=request.scope.get("http_version", "?"),
            client_ip=client_host,
            client_port=client_port,
            content_type=request.headers.get("content-type"),
            content_length=request.headers.get("content-length"),
            scheme=tls["scheme"],
            tls_version=tls["tls_version"],
            cipher=tls["cipher"],
            sni=tls["sni"],
            terminated_at_proxy=tls["terminated_at_proxy"],
        ))

        status_code = 500
        response_length = None

        try:
            response = await call_next(request)
            status_code = response.status_code
            response_length = response.headers.get("content-length")
            return response

        except Exception:
            # Không gửi exception hoặc dữ liệu nội bộ ra dashboard.
            raise

        finally:
            elapsed_ms = round(
                (time.perf_counter() - started) * 1000, 2
            )

            await publish_event(make_event(
                "response_sent",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                response_length=response_length,
                duration_ms=elapsed_ms,
            ))


app.add_middleware(TrafficMonitorMiddleware)


@app.get("/")
async def home():
    return {
        "message": "Python API is running",
        "monitor": "/ws/monitor",
    }


@app.get("/api/test")
async def test():
    return {
        "success": True,
        "message": "Xin chào từ Python server!",
        "images": [
            {"name": "image_001.jpg", "similarity": 0.98},
            {"name": "image_002.jpg", "similarity": 0.94},
            {"name": "image_003.jpg", "similarity": 0.89},
        ],
    }


@app.get("/api/demo")
async def demo():
    return {
        "success": True,
        "message": "Demo request received",
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/tls/scenarios")
async def tls_scenarios():
    """Danh sách kịch bản demo cho tab TLS Visualizer."""
    return {"scenarios": tls_demo.list_scenarios()}


@app.get("/api/tls/scenarios/{scenario_id}")
async def tls_scenario_detail(scenario_id: str):
    s = tls_demo.get_scenario(scenario_id)
    if not s:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="unknown scenario")
    return s


@app.websocket("/ws/monitor")
async def monitor(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)

    try:
        # Gửi lịch sử hiện có cho dashboard mới kết nối.
        await websocket.send_json({
            "type": "history",
            "events": list(event_history),
        })

        # Giữ kết nối sống. Có thể nhận ping từ frontend.
        while True:
            message = await websocket.receive_text()

            if message == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass

    finally:
        connected_clients.discard(websocket)


@app.websocket("/ws/tls")
async def tls_stream(websocket: WebSocket, scenario: str = Query(default="tls13")):
    """Stream từng gói tin của 1 kịch bản, có delay để demo.

    Client: new WebSocket(API/ws/tls?scenario=tls13)
    Server gửi: {type: scenario_info} -> {type: tls_packet}* -> {type: tls_done}
    """
    await websocket.accept()
    s = tls_demo.get_scenario(scenario)
    if not s:
        await websocket.send_json({"type": "error", "detail": "unknown scenario"})
        await websocket.close()
        return
    try:
        await websocket.send_json({
            "type": "scenario_info",
            "id": s["id"], "title": s["title"],
            "description": s["description"],
            "tls_version": s.get("tls_version"),
            "cipher": s.get("cipher"),
            "packet_count": len(s["packets"]),
        })
        for pkt in s["packets"]:
            await asyncio.sleep((pkt.get("delay_ms") or 600) / 1000)
            await websocket.send_json({"type": "tls_packet", "packet": pkt})
        await websocket.send_json({"type": "tls_done"})
        # Giữ kết nối để client replay: nhận {"replay": true} hoặc text scenario id.
        while True:
            msg = await websocket.receive_text()
            if msg in ("replay", "ping"):
                if msg == "ping":
                    await websocket.send_json({"type": "pong"})
                    continue
                for pkt in s["packets"]:
                    await asyncio.sleep((pkt.get("delay_ms") or 600) / 1000)
                    await websocket.send_json({"type": "tls_packet", "packet": pkt})
                await websocket.send_json({"type": "tls_done"})
    except WebSocketDisconnect:
        pass