"""
core/scope.py
=============

Controle de escopo e autorização.

Testes de injeção contra alvos fora de escopo são ilegais e destrutivos. Esta
camada é uma trava dura: nenhuma requisição de ataque sai sem que o host esteja
na allowlist de escopo. A allowlist é derivada dos próprios alvos passados na
linha de comando/arquivo, podendo ser ampliada por domínios explícitos.

Suporta:
  - match exato de host
  - wildcard por sufixo de domínio (ex.: *.exemplo.com)
  - bloqueio explícito (denylist) tem precedência
"""
from __future__ import annotations

from urllib.parse import urlsplit
from typing import Iterable, List


class ScopeError(Exception):
    pass


class Scope:
    def __init__(self, allow: Iterable[str] = (), deny: Iterable[str] = ()):
        self.allow_exact: set[str] = set()
        self.allow_suffix: List[str] = []
        self.deny_exact: set[str] = set()
        self.deny_suffix: List[str] = []
        for a in allow:
            self.add_allow(a)
        for d in deny:
            self.add_deny(d)

    @staticmethod
    def _host(target: str) -> str:
        if "://" not in target:
            target = "http://" + target
        return (urlsplit(target).hostname or "").lower()

    def add_allow(self, rule: str):
        rule = rule.strip().lower()
        if not rule:
            return
        if rule.startswith("*."):
            self.allow_suffix.append(rule[1:])   # ".exemplo.com"
        else:
            self.allow_exact.add(self._host(rule) or rule)

    def add_deny(self, rule: str):
        rule = rule.strip().lower()
        if not rule:
            return
        if rule.startswith("*."):
            self.deny_suffix.append(rule[1:])
        else:
            self.deny_exact.add(self._host(rule) or rule)

    def add_target(self, url: str):
        """Adiciona automaticamente o host de um alvo à allowlist."""
        h = self._host(url)
        if h:
            self.allow_exact.add(h)

    def allows(self, url: str) -> bool:
        h = self._host(url)
        if not h:
            return False
        # deny tem precedência
        if h in self.deny_exact or any(h == s[1:] or h.endswith(s) for s in self.deny_suffix):
            return False
        if h in self.allow_exact:
            return True
        if any(h == s[1:] or h.endswith(s) for s in self.allow_suffix):
            return True
        return False

    def enforce(self, url: str):
        if not self.allows(url):
            raise ScopeError(f"host fora de escopo: {self._host(url)!r} (bloqueado pela trava de escopo)")

    def describe(self) -> str:
        parts = []
        if self.allow_exact:
            parts.append("allow=" + ",".join(sorted(self.allow_exact)))
        if self.allow_suffix:
            parts.append("allow*=" + ",".join(self.allow_suffix))
        if self.deny_exact or self.deny_suffix:
            parts.append("deny=" + ",".join(sorted(self.deny_exact) + self.deny_suffix))
        return " ".join(parts) or "(vazio)"
