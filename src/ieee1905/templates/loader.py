# SPDX-License-Identifier: GPL-2.0-or-later
"""YAML template loader and CMDU builder.

Templates are minimal documents: a message type, a list of TLVs (each
keyed on its dataclass name from :mod:`ieee1905.core.tlvs`), and a set
of free-text ``${var}`` placeholders.

Variable substitution is intentionally simple:
- Placeholders look like ``"${name}"`` (string-typed YAML scalar).
- A single placeholder may be replaced by *any* Python value (int,
  list, hex string, …); whole-string replacement runs first, then
  ``%`` interpolation falls back for embedded substitutions.
- Variables not provided raise :class:`TemplateError` at build time —
  missing inputs are not silently zero.

The TLV dataclasses themselves do the heavy validation; the loader
just wires field names to constructor kwargs and coerces strings to
the right shape (hex → bytes, ``"aa:bb:..."`` → MAC bytes).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ieee1905.core import CMDU, CMDUHeader
from ieee1905.core import tlvs as _tlvs_mod
from ieee1905.core.tlv import encode_typed
from ieee1905.core.tlvs._helpers import parse_mac_str

_PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class TemplateError(ValueError):
    """Raised when a template fails to load or instantiate."""


@dataclass(slots=True)
class Template:
    """Parsed template ready to be instantiated with concrete variables."""

    name: str
    description: str
    message_type: int
    message_id: int | None  # None → auto-assign per build()
    tlvs: list[dict[str, Any]]  # raw TLV dicts (class + field values)
    variables: dict[str, str]  # {name: description} for documentation

    def required_variables(self) -> set[str]:
        out: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, str):
                out.update(_PLACEHOLDER_RE.findall(node))
            elif isinstance(node, dict):
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        for tlv in self.tlvs:
            walk(tlv)
        return out

    def build(
        self,
        variables: dict[str, Any] | None = None,
        *,
        message_id: int | None = None,
    ) -> CMDU:
        """Resolve variables, build TLVs, and return a CMDU."""
        vars_ = dict(variables or {})
        missing = self.required_variables() - set(vars_)
        if missing:
            raise TemplateError(f"missing template variables: {sorted(missing)}")

        mid = (
            message_id
            if message_id is not None
            else (self.message_id if self.message_id is not None else 0)
        )
        cmdu = CMDU(
            header=CMDUHeader(message_type=self.message_type, message_id=mid & 0xFFFF),
            tlvs=[],
        )
        for tlv_dict in self.tlvs:
            resolved = _resolve(tlv_dict, vars_)
            if not isinstance(resolved, dict):
                raise TemplateError(f"TLV entries must be mappings, got {type(resolved).__name__}")
            cmdu.tlvs.append(_build_tlv(resolved))
        return cmdu


def load_template_dict(doc: dict[str, Any]) -> Template:
    """Build a :class:`Template` from an already-parsed YAML mapping."""
    try:
        name = str(doc["name"])
        message_type = _coerce_int(doc["message_type"])
        tlvs = list(doc.get("tlvs") or [])
    except KeyError as exc:
        raise TemplateError(f"template missing required key: {exc}") from exc
    description = str(doc.get("description", ""))
    raw_mid = doc.get("message_id")
    message_id: int | None = None if raw_mid in (None, "auto") else _coerce_int(raw_mid)
    return Template(
        name=name,
        description=description,
        message_type=message_type,
        message_id=message_id,
        tlvs=tlvs,
        variables=dict(doc.get("variables") or {}),
    )


def load_template(path: str | Path) -> Template:
    """Read a YAML template from disk."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TemplateError(f"cannot read template {path}: {exc}") from exc
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TemplateError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise TemplateError(f"template root must be a mapping (got {type(doc).__name__})")
    tpl = load_template_dict(doc)
    return tpl


def builtin_templates_dir() -> Path:
    """Filesystem path to the bundled templates directory."""
    return Path(__file__).parent / "builtin"


def builtin_templates() -> dict[str, Template]:
    """Load every ``*.yaml`` file under :func:`builtin_templates_dir`."""
    out: dict[str, Template] = {}
    for path in sorted(builtin_templates_dir().glob("*.yaml")):
        tpl = load_template(path)
        out[tpl.name] = tpl
    return out


# ---- internals --------------------------------------------------------------


def _resolve(node: Any, variables: dict[str, Any]) -> Any:
    if isinstance(node, str):
        # Whole-string placeholder → return value as-is (lets the variable
        # carry through with its native type, e.g. list / int).
        m = _PLACEHOLDER_RE.fullmatch(node)
        if m:
            return variables[m.group(1)]
        # Embedded placeholders → string interpolation.
        return _PLACEHOLDER_RE.sub(lambda mm: str(variables[mm.group(1)]), node)
    if isinstance(node, dict):
        return {k: _resolve(v, variables) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve(v, variables) for v in node]
    return node


def _build_tlv(spec: dict[str, Any]) -> Any:
    """Convert a resolved TLV dict into a typed-TLV RawTLV via encode_typed."""
    try:
        class_name = spec["class"]
    except KeyError as exc:
        raise TemplateError("TLV entry missing 'class' key") from exc
    cls = getattr(_tlvs_mod, str(class_name), None)
    if cls is None:
        raise TemplateError(f"unknown TLV class: {class_name!r}")
    kwargs = {k: _coerce_field(v) for k, v in spec.items() if k != "class"}
    try:
        instance = cls(**kwargs)
    except TypeError as exc:
        raise TemplateError(f"invalid arguments for {class_name}: {exc}") from exc
    return encode_typed(instance)


def _coerce_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.lower().startswith("0x"):
            return int(v, 16)
        return int(v, 10)
    raise TemplateError(f"expected int, got {type(value).__name__}: {value!r}")


def _coerce_field(value: Any) -> Any:
    """Coerce template-side scalars to the typed-TLV's preferred shape.

    - ``"aa:bb:cc:dd:ee:ff"`` (six hex octets separated by ``:`` or ``-``)
      → ``bytes`` (MAC / OUI / BSSID).
    - ``"hex:0011..."`` or ``"0x0011..."`` → ``bytes``.
    - Anything else passes through unchanged.
    """
    if isinstance(value, list):
        return [_coerce_field(v) for v in value]
    if isinstance(value, dict):
        return {k: _coerce_field(v) for k, v in value.items()}
    if isinstance(value, str):
        if _looks_like_mac(value):
            return parse_mac_str(value)
        low = value.lower()
        if low.startswith("hex:"):
            return bytes.fromhex(low[4:])
        if low.startswith("0x") and all(c in "0123456789abcdef" for c in low[2:]):
            return bytes.fromhex(low[2:])
        if low.startswith("ascii:"):
            return value[6:].encode("ascii")
    return value


def _looks_like_mac(s: str) -> bool:
    parts = s.replace("-", ":").split(":")
    if len(parts) != 6:
        return False
    try:
        for p in parts:
            int(p, 16)
    except ValueError:
        return False
    return True
