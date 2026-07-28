__version__ = "1.1.0"

# NB: NÃO importar .engine aqui — engine importa modules.base, que importa
# core.detector, que reimporta o pacote core -> import circular. A engine é
# importada diretamente por quem precisa (from core.engine import Scanner).
from .target import RequestTemplate, from_url  # noqa: F401
from .http_client import HttpClient  # noqa: F401
from .scope import Scope, ScopeError  # noqa: F401
