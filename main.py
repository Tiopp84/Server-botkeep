import asyncio
import json
import time
from collections import deque
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

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


class TrafficMonitorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Không đưa request giám sát vào log để tránh dashboard tự
        # tạo ra một lượng sự kiện vô hạn.
        if request.url.path == "/ws/monitor":
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