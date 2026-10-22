# app/main.py
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .db import Base, engine
from .wazuh_client import fetch_all_vulns, test_connection
from .schemas.connections import WazuhConnectionRequest, WazuhConnectionResponse
from .schemas.auth import ChangePasswordRequest
from .schemas.users import NewUserRequest
from .services.user_service import create_default_admin
from .services.vuln_service import process_wazuh_vulnerabilities
from .routers import auth_router, users_router, connections_router, vulns_router

# Inicialización de tablas de base de datos
Base.metadata.create_all(bind=engine)

# Constantes y allowlists
CONNECTION_NOT_FOUND = "Conexión no encontrada"
DOMAINS_ALLOWLIST = os.getenv("DOMAINS_ALLOWLIST", "localhost").split(",")

# Crear usuario administrador por defecto
create_default_admin()

# 1. Configurar el Rate Limiter (Requerimiento #4)
# limit="5/minute" significa máximo 5 peticiones por minuto por IP
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# Instancia de FastAPI
app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

# 2. Registrar el limitador y su manejador de errores en la App
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middlewares
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registro de controladores (Routers)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(connections_router)
app.include_router(vulns_router)