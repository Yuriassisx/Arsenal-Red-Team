"""
modules/base.py
===============

Definição de um módulo de vulnerabilidade orientado a dados (YAML) e o modelo
de achado (Finding).

Um módulo declara:
  name, description
  detectors   : estratégias de detecção aplicáveis
  signatures  : regex de evidência forte (para o detector 'signature')
  transforms  : conjunto de encoders/bypass aplicados a cada payload
  payloads    : lista de payloads, cada um com value + tags + (delay | oob)

Placeholders suportados no valor do payload:
  {MARK}    -> marcador único de reflexão (detecção reflection)
  {OOBURL}  -> URL de callback OOB (http://host:porta/token)
  {OOBHOST} -> host:porta/token de callback OOB (sem esquema)
  {OOBFQDN} -> apenas host (para payloads que concatenam esquema próprio)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Any

import yaml

from core.detector import compile_signatures


@dataclass
class Payload:
    value: str
    tags: List[str] = field(default_factory=list)
    delay: float = 0.0          # >0 => payload time-based
    oob: bool = False           # usa callback OOB
    note: str = ""


@dataclass
class Finding:
    module: str
    point: str                  # "query:id"
    method: str
    url: str
    payload: str                # variante enviada
    base_payload: str           # payload lógico (antes do transform)
    transform: str
    confidence: float
    detectors: List[str]
    evidence: str
    tags: List[str] = field(default_factory=list)
    repro: str = ""             # comando curl pronto p/ reproduzir manualmente

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "point": self.point,
            "method": self.method,
            "url": self.url,
            "payload": self.payload,
            "base_payload": self.base_payload,
            "transform": self.transform,
            "confidence": round(self.confidence, 2),
            "detectors": self.detectors,
            "evidence": self.evidence,
            "tags": self.tags,
            "repro": self.repro,
        }


class Module:
    def __init__(self, spec: dict):
        self.name: str = spec["name"]
        self.description: str = spec.get("description", "")
        self.detectors: List[str] = spec.get("detectors", ["signature"])
        self.transforms: List[str] = spec.get("transforms", ["url"])
        self.signatures = compile_signatures(spec.get("signatures", []))
        self.raw_signatures: List[str] = spec.get("signatures", [])
        self.diff_len_ratio: float = float(spec.get("diff_len_ratio", 0.30))
        self.time_margin: float = float(spec.get("time_margin", 1.5))
        # True = as assinaturas do módulo representam o payload refletido (XSS),
        # então NÃO suprimir match que também aparece no input injetado.
        self.reflected_signatures: bool = bool(spec.get("reflected_signatures", False))
        # pares booleanos p/ confirmação (oráculo verdadeiro/falso) — SQLi/NoSQLi.
        # NB: no YAML as chaves true/false viram bool -> normaliza p/ string.
        self.boolean_pairs: list = [
            {str(k).lower(): v for k, v in pair.items()}
            for pair in (spec.get("boolean_pairs", []) or [])
        ]
        self.payloads: List[Payload] = []
        for p in spec.get("payloads", []):
            if isinstance(p, str):
                self.payloads.append(Payload(value=p))
            else:
                self.payloads.append(Payload(
                    value=p["value"],
                    tags=[str(t) for t in p.get("tags", [])],  # YAML pode virar bool/None
                    delay=float(p.get("delay", 0.0)),
                    oob=bool(p.get("oob", False)),
                    note=p.get("note", ""),
                ))

    @property
    def uses_oob(self) -> bool:
        return "oob" in self.detectors or any(p.oob for p in self.payloads)

    @classmethod
    def from_file(cls, path: str) -> "Module":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))


def load_modules(payload_dir: str, only: Optional[List[str]] = None) -> List[Module]:
    mods = []
    for fn in sorted(os.listdir(payload_dir)):
        if not fn.endswith((".yaml", ".yml")):
            continue
        name = os.path.splitext(fn)[0]
        if only and name not in only:
            continue
        mods.append(Module.from_file(os.path.join(payload_dir, fn)))
    return mods
