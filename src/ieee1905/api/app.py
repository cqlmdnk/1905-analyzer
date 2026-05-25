# SPDX-License-Identifier: GPL-2.0-or-later
"""FastAPI backend skeleton.

Phase 0 only exposes meta endpoints (``/api/version``, ``/api/interfaces``,
``/api/privileges``). Capture, inject, bridge, plugin, and conformance
endpoints arrive in later phases.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import tempfile
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ieee1905 import __version__
from ieee1905.api.auth import current_token, require_token
from ieee1905.io import check_privileges, list_interfaces
from ieee1905.logging_setup import configure as configure_logging

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title="ieee1905-suite",
        version=__version__,
        description="IEEE 1905.1 + EasyMesh analyzer/injector/bridge suite (Phase 0 skeleton).",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["X-API-Token", "Content-Type"],
    )

    @app.get("/api/version")
    def version() -> dict[str, str]:
        return {"version": __version__}

    @app.get("/api/privileges", dependencies=[Depends(require_token)])
    def privileges() -> dict[str, Any]:
        pc = check_privileges()
        return {
            "ok": pc.ok,
            "platform": pc.platform,
            "detail": pc.detail,
            "hint": pc.hint,
        }

    @app.get("/api/interfaces", dependencies=[Depends(require_token)])
    def interfaces() -> list[dict[str, Any]]:
        return [
            {
                "name": i.name,
                "mac": i.mac,
                "description": i.description,
                "is_loopback": i.is_loopback,
                "is_up": i.is_up,
            }
            for i in list_interfaces()
        ]

    _register_capture_endpoints(app)
    _register_inject_endpoints(app)
    _register_template_endpoints(app)

    return app


# --- pcap upload + decode -----------------------------------------------------


def _frame_to_dict(frame: Any) -> dict[str, Any]:
    """Render a CapturedFrame as a JSON-friendly dict."""
    from ieee1905.core import MessageType

    out: dict[str, Any] = {
        "timestamp": frame.timestamp,
        "src_mac": frame.src_mac.hex(":") if frame.src_mac else None,
        "dst_mac": frame.dst_mac.hex(":") if frame.dst_mac else None,
        "ethertype": frame.ethertype,
        "raw_length": len(frame.raw),
    }
    if frame.cmdu is not None:
        hdr = frame.cmdu.header
        out["cmdu"] = {
            "message_type": hdr.message_type,
            "message_type_name": MessageType.describe(hdr.message_type),
            "message_id": hdr.message_id,
            "fragment_id": hdr.fragment_id,
            "last_fragment": hdr.last_fragment,
            "relay_indicator": hdr.relay_indicator,
            "tlvs": [_tlv_to_dict(t) for t in frame.cmdu.typed_tlvs()],
        }
    else:
        out["decode_error"] = frame.decode_error
    return out


def _tlv_to_dict(typed_tlv: Any) -> dict[str, Any]:
    """Render a typed TLV (or RawTLV on registry miss) as JSON-friendly dict."""
    from ieee1905.core import RawTLV
    from ieee1905.core.tlv_types import TLVType

    if isinstance(typed_tlv, RawTLV):
        return {
            "kind": "raw",
            "type": typed_tlv.tlv_type,
            "type_name": TLVType.describe(typed_tlv.tlv_type),
            "length": typed_tlv.length,
            "payload_hex": typed_tlv.payload.hex(),
        }
    cls = type(typed_tlv)
    return {
        "kind": "typed",
        "class": cls.__name__,
        "type": getattr(cls, "TLV_TYPE", None),
        "type_name": getattr(cls, "TLV_NAME", cls.__name__),
        "fields": _serialize_fields(typed_tlv),
    }


def _serialize_fields(obj: Any) -> Any:
    """Convert dataclass / dict / list / bytes into JSON-serializable forms."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _serialize_fields(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_serialize_fields(x) for x in obj]
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize_fields(v) for k, v in asdict(obj).items()}
    return obj


def _register_capture_endpoints(app: FastAPI) -> None:
    """Endpoints for reading PCAPs and streaming live frames."""

    @app.post("/api/pcap/decode", dependencies=[Depends(require_token)])
    async def pcap_decode(file: UploadFile) -> dict[str, Any]:
        """Upload a PCAP / PCAPNG and get the decoded 1905 frames back."""
        from ieee1905.io.pcap import iter_pcap

        if file.filename is None:
            raise HTTPException(status_code=400, detail="missing filename")
        suffix = Path(file.filename).suffix or ".pcap"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        try:
            frames = [_frame_to_dict(f) for f in iter_pcap(tmp_path, ieee1905_only=True)]
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        return {"filename": file.filename, "frame_count": len(frames), "frames": frames}

    @app.websocket("/ws/frames/{interface}")
    async def live_frames(ws: WebSocket, interface: str) -> None:
        """Stream live 1905 frames from ``interface`` over WebSocket.

        Client must send ``{"token": "..."}`` as the first message; otherwise
        the connection is closed. Each subsequent server message is a
        decoded :class:`CapturedFrame` dict.
        """
        from ieee1905.core import CMDU
        from ieee1905.core.cmdu import CMDUParseError
        from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
        from ieee1905.io.ethernet import EthernetFrame, EthernetParseError
        from ieee1905.io.pcap import CapturedFrame

        await ws.accept()
        try:
            handshake = await asyncio.wait_for(ws.receive_json(), timeout=10.0)
        except (TimeoutError, Exception):
            await ws.close(code=4001)
            return
        if not isinstance(handshake, dict) or handshake.get("token") != current_token():
            await ws.close(code=4003)
            return

        loop = asyncio.get_running_loop()
        stop = threading.Event()
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=512)

        def on_frame(raw: bytes, ts: float) -> None:
            try:
                eth = EthernetFrame.parse(raw)
            except EthernetParseError:
                return
            if eth.ethertype != ETHERTYPE_IEEE1905:
                return
            try:
                cmdu = CMDU.from_bytes(eth.payload)
                err: str | None = None
            except CMDUParseError as exc:
                cmdu = None
                err = f"cmdu parse: {exc}"
            cap = CapturedFrame(
                timestamp=ts,
                raw=raw,
                src_mac=eth.src,
                dst_mac=eth.dst,
                ethertype=eth.ethertype,
                cmdu=cmdu,
                decode_error=err,
            )
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(queue.put_nowait, _frame_to_dict(cap))

        def sniffer() -> None:
            backend = get_default_backend()
            try:
                with backend.open_live(interface, promiscuous=True) as live:
                    live.sniff(on_frame, stop_event=stop)
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        worker = threading.Thread(target=sniffer, daemon=True)
        worker.start()
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                await ws.send_json(item)
        except WebSocketDisconnect:
            pass
        finally:
            stop.set()
            worker.join(timeout=2.0)


# --- inject -------------------------------------------------------------------


class InjectRequest(BaseModel):
    interface: str
    frame_hex: str = Field(..., description="Hex-encoded CMDU payload (no ethernet header).")
    repeat: int = Field(1, ge=1, le=100_000)
    dst_mac: str = "01:80:c2:00:00:13"
    src_mac: str | None = None


class ReplayRequest(BaseModel):
    interface: str
    pcap_path: str = Field(..., description="Server-side path to a PCAP/PCAPNG file.")
    speed: float = Field(1.0, description="Timing multiplier. 0 = back-to-back.")
    loop: bool = False
    ieee1905_only: bool = True


class InjectTemplateRequest(BaseModel):
    interface: str
    template: str = Field(..., description="Built-in template name.")
    variables: dict[str, Any] = Field(default_factory=dict)
    dst_mac: str = "01:80:c2:00:00:13"
    src_mac: str | None = None
    profile: int = 1


def _register_inject_endpoints(app: FastAPI) -> None:
    @app.post("/api/inject", dependencies=[Depends(require_token)])
    def inject(req: InjectRequest) -> dict[str, Any]:
        from ieee1905.core.tlvs._helpers import parse_mac_str
        from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
        from ieee1905.io.ethernet import EthernetFrame
        from ieee1905.io.interfaces import list_interfaces

        try:
            payload = bytes.fromhex(req.frame_hex)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"bad frame_hex: {exc}") from exc
        try:
            dst = parse_mac_str(req.dst_mac)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"bad dst_mac: {exc}") from exc
        src: bytes
        if req.src_mac is not None:
            src = parse_mac_str(req.src_mac)
        else:
            resolved: bytes | None = None
            for iface in list_interfaces():
                if iface.name == req.interface and iface.mac:
                    resolved = parse_mac_str(iface.mac)
                    break
            if resolved is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"could not determine source MAC for {req.interface}",
                )
            src = resolved

        frame_bytes = EthernetFrame(
            dst=dst, src=src, ethertype=ETHERTYPE_IEEE1905, payload=payload
        ).to_bytes()
        backend = get_default_backend()
        with backend.open_live(req.interface, bpf_filter=None, promiscuous=False) as live:
            for _ in range(req.repeat):
                live.inject(frame_bytes)
        return {"injected": req.repeat, "interface": req.interface}

    @app.post("/api/pcap/replay", dependencies=[Depends(require_token)])
    def replay(req: ReplayRequest) -> dict[str, Any]:
        from ieee1905.io.pcap import replay_pcap

        if not Path(req.pcap_path).is_file():
            raise HTTPException(status_code=404, detail=f"no such file: {req.pcap_path}")
        try:
            stats = replay_pcap(
                req.pcap_path,
                req.interface,
                speed=req.speed,
                loop=req.loop,
                ieee1905_only=req.ieee1905_only,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {
            "interface": req.interface,
            "pcap_path": req.pcap_path,
            "total_frames": stats.total_frames,
            "injected": stats.injected,
            "skipped_non_1905": stats.skipped_non_1905,
            "skipped_malformed": stats.skipped_malformed,
            "duration_s": stats.duration_s,
        }


def _register_template_endpoints(app: FastAPI) -> None:
    """List built-in templates and build/inject a CMDU from one."""

    @app.get("/api/templates", dependencies=[Depends(require_token)])
    def list_templates() -> list[dict[str, Any]]:
        from ieee1905.templates import builtin_templates

        return [
            {
                "name": tpl.name,
                "description": tpl.description,
                "message_type": tpl.message_type,
                "variables": sorted(tpl.required_variables()),
                "variable_docs": tpl.variables,
            }
            for tpl in builtin_templates().values()
        ]

    @app.post("/api/inject/template", dependencies=[Depends(require_token)])
    def inject_template(req: InjectTemplateRequest) -> dict[str, Any]:
        from ieee1905.core.tlvs._helpers import parse_mac_str
        from ieee1905.io.backend import ETHERTYPE_IEEE1905, get_default_backend
        from ieee1905.io.ethernet import EthernetFrame
        from ieee1905.io.interfaces import list_interfaces
        from ieee1905.templates import TemplateError, builtin_templates

        templates = builtin_templates()
        if req.template not in templates:
            raise HTTPException(
                status_code=404,
                detail=f"unknown template {req.template!r}; "
                f"available: {sorted(templates)}",
            )
        try:
            cmdu = templates[req.template].build(req.variables)
        except TemplateError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        payload = cmdu.to_bytes(profile=req.profile if req.profile >= 2 else None)

        try:
            dst = parse_mac_str(req.dst_mac)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"bad dst_mac: {exc}") from exc

        src: bytes
        if req.src_mac is not None:
            src = parse_mac_str(req.src_mac)
        else:
            resolved: bytes | None = None
            for iface in list_interfaces():
                if iface.name == req.interface and iface.mac:
                    resolved = parse_mac_str(iface.mac)
                    break
            if resolved is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"could not determine source MAC for {req.interface}",
                )
            src = resolved

        frame_bytes = EthernetFrame(
            dst=dst, src=src, ethertype=ETHERTYPE_IEEE1905, payload=payload
        ).to_bytes()
        backend = get_default_backend()
        with backend.open_live(req.interface, bpf_filter=None, promiscuous=False) as live:
            live.inject(frame_bytes)
        return {
            "template": req.template,
            "interface": req.interface,
            "message_type": cmdu.header.message_type,
            "tlv_count": len(cmdu.tlvs),
            "payload_bytes": len(payload),
        }


def run(host: str = "127.0.0.1", port: int = 8519, reload: bool = False) -> None:
    import uvicorn

    configure_logging()
    token = current_token()
    logger.info("API token: %s", token)
    logger.info("Bind: http://%s:%d/api/version", host, port)
    uvicorn.run(
        "ieee1905.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
        log_config=None,
    )
