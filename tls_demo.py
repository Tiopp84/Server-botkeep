"""Kịch bản demo TLS/SSL giả lập cho dạy học (hướng A).

Không sniff packet thật — trả chuỗi gói tin có kịch bản để
Static_Web render kiểu Wireshark: Packet List / Detail Tree / Hex Dump.
"""
from __future__ import annotations

# Mỗi packet là dict JSON-serializable:
# no, delay_ms, src, dst, protocol, info, length, encrypted,
# layers {tcp, tls/http}, hex, plain, note

def _tcp(flags: str, seq=0, ack=0, sport=52344, dport=443):
    return {
        "sport": sport, "dport": dport,
        "seq": seq, "ack": ack, "flags": flags,
        "window": 64240, "len": 0,
    }


CLIENT = "client (browser)"
SERVER = "server (fastapi)"


def scenario_http_plain():
    return {
        "id": "http-plain",
        "title": "HTTP plain (không mã hoá)",
        "description": "Cùng 1 request GET /api/demo nhưng gửi qua HTTP. Mọi byte đều đọc được — dùng để đối chiếu với HTTPS.",
        "tls_version": "none",
        "cipher": "none",
        "sni": "demo.bot-keep.xyz",
        "packets": [
            {"no": 1, "delay_ms": 300, "src": CLIENT, "dst": SERVER, "protocol": "TCP", "info": "SYN  Seq=0", "length": 66, "encrypted": False,
             "layers": {"tcp": _tcp("SYN", seq=0)}, "hex": "00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 00 3c ... flags [SYN]",
             "plain": None, "note": "Bắt tay TCP 3 bước: đồng bộ số sequence."},
            {"no": 2, "delay_ms": 400, "src": SERVER, "dst": CLIENT, "protocol": "TCP", "info": "SYN, ACK  Seq=0 Ack=1", "length": 66, "encrypted": False,
             "layers": {"tcp": _tcp("SYN,ACK", seq=0, ack=1, sport=80, dport=52344)}, "hex": "… flags [SYN, ACK]",
             "plain": None, "note": "Server đồng ý kết nối."},
            {"no": 3, "delay_ms": 400, "src": CLIENT, "dst": SERVER, "protocol": "TCP", "info": "ACK  Seq=1 Ack=1", "length": 54, "encrypted": False,
             "layers": {"tcp": _tcp("ACK", seq=1, ack=1)}, "hex": "… flags [ACK]",
             "plain": None, "note": "Kết nối TCP đã sẵn sàng. Chưa có mã hoá gì cả."},
            {"no": 4, "delay_ms": 700, "src": CLIENT, "dst": SERVER, "protocol": "HTTP", "info": "GET /api/demo HTTP/1.1", "length": 412, "encrypted": False,
             "layers": {"tcp": _tcp("PSH,ACK", seq=1, ack=1), "http": {"method": "GET", "path": "/api/demo", "host": "demo.bot-keep.xyz", "user_agent": "Mozilla/5.0 …"}},
             "hex": "47 45 54 20 2f 61 70 69 2f 64 65 6d 6f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 …",
             "plain": "GET /api/demo HTTP/1.1\r\nHost: demo.bot-keep.xyz\r\nUser-Agent: Mozilla/5.0 …\r\n",
             "note": "ATTACKER ĐỌC ĐƯỢC toàn bộ: method, path, header, cookie. Hex decode ra ASCII ngay."},
            {"no": 5, "delay_ms": 700, "src": SERVER, "dst": CLIENT, "protocol": "HTTP", "info": "HTTP/1.1 200 OK (application/json)", "length": 523, "encrypted": False,
             "layers": {"tcp": _tcp("PSH,ACK", seq=1, ack=413, sport=80, dport=52344), "http": {"status": "200 OK", "content_type": "application/json"}},
             "hex": "48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 65 …",
             "plain": 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"success": true, "message": "Demo request received"}',
             "note": "Response cũng lộ toàn bộ body JSON. Đây là lý do phải dùng TLS."},
        ],
    }


def scenario_tls13():
    return {
        "id": "tls13",
        "title": "HTTPS + TLS 1.3 (1-RTT)",
        "description": "Handshake TLS 1.3 hiện đại: ít round-trip hơn 1.2, mọi thứ sau ServerHello đều mã hoá, không còn ChangeCipherSpec riêng.",
        "tls_version": "TLS 1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "sni": "demo.bot-keep.xyz",
        "packets": [
            {"no": 1, "delay_ms": 300, "src": CLIENT, "dst": SERVER, "protocol": "TCP", "info": "SYN  Seq=0", "length": 66, "encrypted": False,
             "layers": {"tcp": _tcp("SYN")}, "hex": "… flags [SYN]", "plain": None,
             "note": "TCP handshake trước, giống hệt HTTP."},
            {"no": 2, "delay_ms": 350, "src": SERVER, "dst": CLIENT, "protocol": "TCP", "info": "SYN, ACK", "length": 66, "encrypted": False,
             "layers": {"tcp": _tcp("SYN,ACK", sport=443, dport=52344)}, "hex": "… flags [SYN, ACK]", "plain": None, "note": ""},
            {"no": 3, "delay_ms": 350, "src": CLIENT, "dst": SERVER, "protocol": "TCP", "info": "ACK", "length": 54, "encrypted": False,
             "layers": {"tcp": _tcp("ACK")}, "hex": "… flags [ACK]", "plain": None, "note": ""},
            {"no": 4, "delay_ms": 800, "src": CLIENT, "dst": SERVER, "protocol": "TLSv1.3", "info": "Client Hello (SNI, key_share X25519, ALPN h2)", "length": 512, "encrypted": False,
             "layers": {"tcp": _tcp("PSH,ACK", seq=1, ack=1), "tls": {"type": "ClientHello", "version": "TLS 1.2 (JJ hello, negotiate 1.3)", "sni": "demo.bot-keep.xyz", "alpn": ["h2", "http/1.1"], "key_share": "X25519 public (32B)", "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]}},
             "hex": "16 03 01 02 00 01 00 01 fc 03 03 cb 34 ec … 00 00 00 0e 00 0c 00 00 09 64 65 6d 6f … (SNI cleartext)",
             "plain": "TLS ClientHello: SNI=demo.bot-keep.xyz, ALPN=h2 — VẪN ĐỌC ĐƯỢC (chưa mã hoá). Kẻ nghe lén biết bạn vào domain nào.",
             "note": "Điểm dạy học: SNI lộ trừ khi dùng ECH. key_share gửi luôn nên chỉ cần 1-RTT."},
            {"no": 5, "delay_ms": 800, "src": SERVER, "dst": CLIENT, "protocol": "TLSv1.3", "info": "Server Hello (key_share, TLS_AES_128_GCM_SHA256)", "length": 122, "encrypted": False,
             "layers": {"tcp": _tcp("PSH,ACK", sport=443, dport=52344), "tls": {"type": "ServerHello", "version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "key_share": "X25519 public (32B)"}},
             "hex": "16 03 03 00 7a 02 00 00 76 03 03 7f 2a … 13 01 (cipher 0x1301)",
             "plain": "ServerHello: chốt cipher TLS_AES_128_GCM_SHA256. Đây là gói cleartext CUỐI CÙNG.",
             "note": "Từ đây hai bên đã tính được handshake secret (ECDHE X25519)."},
            {"no": 6, "delay_ms": 800, "src": SERVER, "dst": CLIENT, "protocol": "TLSv1.3", "info": "{EncryptedExtensions} {Certificate} {CertificateVerify} {Finished}", "length": 2840, "encrypted": True,
             "layers": {"tcp": _tcp("PSH,ACK", sport=443, dport=52344), "tls": {"type": "EncryptedExtensions + Certificate + Finished", "cert_cn": "CN=*.bot-keep.xyz", "issuer": "Let's Encrypt R11", "alpn_selected": "h2"}},
             "hex": "17 03 03 0b 10 8f 3a 9c e4 71 b2 … (toàn bộ là ciphertext, không decode được)",
             "plain": None,
             "note": "KHÁC TLS 1.2: certificate đã được MÃ HOÁ. Wireshark không có keylog thì chỉ thấy Application Data."},
            {"no": 7, "delay_ms": 700, "src": CLIENT, "dst": SERVER, "protocol": "TLSv1.3", "info": "{Finished} (client auth done)", "length": 80, "encrypted": True,
             "layers": {"tls": {"type": "Finished", "verify": "HMAC(handshake_secret)"}}, "hex": "17 03 03 00 40 2a 9f 3c d1 …",
             "plain": None, "note": "Client xác nhận đã tính đúng session key. Handshake xong sau ~1-RTT."},
            {"no": 8, "delay_ms": 700, "src": CLIENT, "dst": SERVER, "protocol": "TLSv1.3", "info": "Application Data: GET /api/demo", "length": 328, "encrypted": True,
             "layers": {"tls": {"type": "ApplicationData"}}, "hex": "17 03 03 01 20 9e f2 77 01 c4 … (không thấy GET, không thấy path)",
             "plain": " attacker thấy: 17 03 03 … ciphertext. GIẢI MÃ (với key): GET /api/demo HTTP/2",
             "note": "So với gói số 4 của HTTP-plain: cùng request nhưng giờ đã ẩn hoàn toàn."},
            {"no": 9, "delay_ms": 700, "src": SERVER, "dst": CLIENT, "protocol": "TLSv1.3", "info": "Application Data: HTTP 200 JSON", "length": 412, "encrypted": True,
             "layers": {"tls": {"type": "ApplicationData"}}, "hex": "17 03 03 01 6a 41 bc 0d 55 …",
             "plain": "GIẢI MÃ (với key): {\"success\": true, \"message\": \"Demo request received\"}",
             "note": "Body JSON cũng được bảo vệ. Đây là điều dashboard L7 của bạn thấy sau khi terminate TLS."},
        ],
    }


def scenario_tls12():
    return {
        "id": "tls12",
        "title": "HTTPS + TLS 1.2 (2-RTT, legacy)",
        "description": "Handshake TLS 1.2 dài hơn: Certificate gửi cleartext, có thêm ChangeCipherSpec riêng. Dùng để so sánh với 1.3.",
        "tls_version": "TLS 1.2",
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "sni": "demo.bot-keep.xyz",
        "packets": [
            {"no": 1, "delay_ms": 300, "src": CLIENT, "dst": SERVER, "protocol": "TCP", "info": "SYN / SYN-ACK / ACK", "length": 66, "encrypted": False,
             "layers": {"tcp": _tcp("SYN")}, "hex": "… 3-way handshake (gộp cho gọn)", "plain": None, "note": "TCP handshake gộp thành 1 dòng cho gọn khi demo."},
            {"no": 2, "delay_ms": 800, "src": CLIENT, "dst": SERVER, "protocol": "TLSv1.2", "info": "Client Hello (SNI, ECDHE suites)", "length": 480, "encrypted": False,
             "layers": {"tls": {"type": "ClientHello", "version": "TLS 1.2", "sni": "demo.bot-keep.xyz", "cipher_suites": ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"]}},
             "hex": "16 03 01 01 df 01 00 01 db 03 03 … SNI cleartext", "plain": "ClientHello cleartext — lộ SNI.", "note": ""},
            {"no": 3, "delay_ms": 800, "src": SERVER, "dst": CLIENT, "protocol": "TLSv1.2", "info": "Server Hello, Certificate (CLEARTEXT!), ServerHelloDone", "length": 3420, "encrypted": False,
             "layers": {"tls": {"type": "ServerHello + Certificate + ServerHelloDone", "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "cert_cn": "CN=*.bot-keep.xyz (GỬI TRẦN, chưa mã hoá)"}},
             "hex": "16 03 03 00 4d 02 … 16 03 03 0c a0 0b 00 0c 9c 30 82 0c 98 … (cert DER đọc được)",
             "plain": "Certificate DER: CN=*.bot-keep.xyz, Issuer=Let's Encrypt — AI CŨNG ĐỌC ĐƯỢC. Đây là khác biệt lớn nhất với TLS 1.3.",
             "note": "Wireshark không cần key vẫn xem được cert ở TLS 1.2."},
            {"no": 4, "delay_ms": 800, "src": CLIENT, "dst": SERVER, "protocol": "TLSv1.2", "info": "ClientKeyExchange, ChangeCipherSpec, Finished", "length": 220, "encrypted": False,
             "layers": {"tls": {"type": "ClientKeyExchange (ECDHE pubkey) + CCS + Finished"}}, "hex": "16 03 03 00 46 10 … 14 03 03 00 01 01 …",
             "plain": "Client gửi ECDHE public key (cleartext) rồi bật mã hoá từ gói Finished.",
             "note": "Có gói ChangeCipherSpec (0x14) riêng — TLS 1.3 đã bỏ."},
            {"no": 5, "delay_ms": 700, "src": SERVER, "dst": CLIENT, "protocol": "TLSv1.2", "info": "ChangeCipherSpec, Finished", "length": 100, "encrypted": True,
             "layers": {"tls": {"type": "CCS + Finished"}}, "hex": "14 03 03 00 01 01 16 03 03 00 40 …",
             "plain": None, "note": "Từ đây mới mã hoá. Tổng 2-RTT, chậm hơn TLS 1.3."},
            {"no": 6, "delay_ms": 700, "src": CLIENT, "dst": SERVER, "protocol": "TLSv1.2", "info": "Application Data (Encrypted): GET /api/demo", "length": 330, "encrypted": True,
             "layers": {"tls": {"type": "ApplicationData"}}, "hex": "17 03 03 01 20 … ciphertext",
             "plain": "Giải mã: GET /api/demo", "note": ""},
        ],
    }


def scenario_mitm():
    return {
        "id": "mitm-selfsigned",
        "title": "Tấn công MITM (cert tự ký) — THẤT BẠI",
        "description": "Attacker chặn giữa, trả cert giả. Browser phát hiện sai chain và báo lỗi. Demo vì sao CA + verify quan trọng.",
        "tls_version": "TLS 1.2 (attack)",
        "cipher": "— (handshake aborted)",
        "sni": "demo.bot-keep.xyz",
        "packets": [
            {"no": 1, "delay_ms": 400, "src": CLIENT, "dst": "attacker", "protocol": "TLSv1.2", "info": "Client Hello (SNI=demo.bot-keep.xyz)", "length": 480, "encrypted": False,
             "layers": {"tls": {"type": "ClientHello", "sni": "demo.bot-keep.xyz"}}, "hex": "16 03 01 … SNI cleartext — attacker biết nạn nhân vào đâu",
             "plain": "ClientHello lộ SNI nên attacker biết cần giả domain nào.", "note": ""},
            {"no": 2, "delay_ms": 800, "src": "attacker", "dst": CLIENT, "protocol": "TLSv1.2", "info": "Certificate FAKE: CN=demo.bot-keep.xyz, Issuer=Attacker-CA", "length": 1800, "encrypted": False,
             "layers": {"tls": {"type": "Certificate (FAKE)", "cert_cn": "CN=demo.bot-keep.xyz", "issuer": "Attacker-CA (KHÔNG TRUSTED)", "valid": False}},
             "hex": "16 03 03 … 30 82 … Issuer: Attacker-CA …",
             "plain": "Cert nhìn giống thật (đúng CN) nhưng Issuer lạ, không nằm trong trust store.",
             "note": "BROWSER DỪNG LẠI: NET::ERR_CERT_AUTHORITY_INVALID."},
            {"no": 3, "delay_ms": 600, "src": CLIENT, "dst": "attacker", "protocol": "TLSv1.2", "info": "Alert (Level: Fatal, Bad Certificate) + FIN", "length": 80, "encrypted": False,
             "layers": {"tls": {"type": "Alert", "level": "Fatal (2)", "description": "Bad Certificate (42)"}}, "hex": "15 03 03 00 02 02 2a",
             "plain": "0x15 = Alert, 0x02 0x2a = Fatal/Bad Certificate.", "note": "Handshake bị huỷ, không gói Application Data nào được gửi. Nếu user bấm 'Proceed unsafe' thì attacker mới đọc được traffic."},
        ],
    }


def scenario_expired():
    return {
        "id": "expired-cert",
        "title": "Cert hết hạn — cảnh báo",
        "description": "Server dùng cert đúng CA nhưng đã hết hạn. Browser vẫn cảnh báo dù không có attacker.",
        "tls_version": "TLS 1.3",
        "cipher": "— (user phải xác nhận)",
        "sni": "demo.bot-keep.xyz",
        "packets": [
            {"no": 1, "delay_ms": 400, "src": CLIENT, "dst": SERVER, "protocol": "TLSv1.3", "info": "Client Hello", "length": 512, "encrypted": False,
             "layers": {"tls": {"type": "ClientHello", "sni": "demo.bot-keep.xyz"}}, "hex": "16 03 01 …", "plain": None, "note": ""},
            {"no": 2, "delay_ms": 700, "src": SERVER, "dst": CLIENT, "protocol": "TLSv1.3", "info": "{Certificate}: NotAfter đã qua 12 ngày", "length": 2400, "encrypted": True,
             "layers": {"tls": {"type": "Certificate (decrypted with key)", "cert_cn": "CN=*.bot-keep.xyz", "not_after": "expired 12 days ago", "valid": False}},
             "hex": "17 03 03 … (cần keylog mới xem được trong TLS 1.3)", "plain": "Decrypted: Validity NotAfter=2026-10-01 (expired). Issuer vẫn đúng Let's Encrypt.",
             "note": "Bài học: TLS 1.3 giấu cert khỏi người nghe lén, nhưng client vẫn verify và báo lỗi NET::ERR_CERT_DATE_INVALID."},
        ],
    }


SCENARIOS: dict[str, callable] = {
    "http-plain": scenario_http_plain,
    "tls13": scenario_tls13,
    "tls12": scenario_tls12,
    "mitm-selfsigned": scenario_mitm,
    "expired-cert": scenario_expired,
}


def list_scenarios():
    out = []
    for sid, fn in SCENARIOS.items():
        s = fn()
        out.append({k: v for k, v in s.items() if k != "packets"} | {"packet_count": len(s["packets"])})
    return out


def get_scenario(sid: str):
    fn = SCENARIOS.get(sid)
    return fn() if fn else None
