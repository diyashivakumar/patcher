"""Consistent error format for every endpoint:  {"error": {"code", "message", "details"}}"""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.database import DatabaseNotConfigured


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str, details=None):
        self.status_code, self.code, self.message, self.details = status_code, code, message, details


def not_found(what: str):
    return ApiError(404, "not_found", f"{what} not found")


def _body(code, message, details=None):
    return {"error": {"code": code, "message": message, "details": details}}


def install_error_handlers(app: FastAPI):
    @app.exception_handler(ApiError)
    async def api_error(_req: Request, exc: ApiError):
        return JSONResponse(status_code=exc.status_code, content=_body(exc.code, exc.message, exc.details))

    @app.exception_handler(RequestValidationError)
    async def validation_error(_req: Request, exc: RequestValidationError):
        details = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content=_body("validation_error", "Request validation failed", details))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_req: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return JSONResponse(status_code=exc.status_code, content=_body(code, str(exc.detail)))

    @app.exception_handler(DatabaseNotConfigured)
    async def db_not_configured(_req: Request, exc: DatabaseNotConfigured):
        return JSONResponse(status_code=503, content=_body("database_not_configured", str(exc)))
