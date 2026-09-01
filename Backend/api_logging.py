
# This file handles api logging.
from __future__ import annotations

import inspect
import logging
from functools import wraps
from time import perf_counter

from fastapi import HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute


# Uvicorn already configures this logger for terminal output when start.sh runs.
logger = logging.getLogger("uvicorn.error")


# Work with logged layer method.
def _logged_layer_method(method, layer: str):

    method_name = f"{method.__module__}.{method.__qualname__}"

    if inspect.iscoroutinefunction(method):

        # Log an asynchronous function call.
        @wraps(method)
        async def async_wrapper(*args, **kwargs):
            started_at = perf_counter()
            logger.info("API %s calling | function=%s", layer, method_name)
            try:
                result = await method(*args, **kwargs)
            except HTTPException as exc:
                logger.info(
                    "API %s rejected | function=%s | status=%s",
                    layer,
                    method_name,
                    exc.status_code,
                )
                raise
            except Exception:
                logger.exception("API %s failed | function=%s", layer, method_name)
                raise
            logger.info(
                "API %s returned | function=%s | duration=%.1fms",
                layer,
                method_name,
                (perf_counter() - started_at) * 1000,
            )
            return result

        return async_wrapper

    # Work with sync wrapper.
    @wraps(method)
    def sync_wrapper(*args, **kwargs):
        started_at = perf_counter()
        logger.info("API %s calling | function=%s", layer, method_name)
        try:
            result = method(*args, **kwargs)
        except HTTPException as exc:
            logger.info(
                "API %s rejected | function=%s | status=%s",
                layer,
                method_name,
                exc.status_code,
            )
            raise
        except Exception:
            logger.exception("API %s failed | function=%s", layer, method_name)
            raise
        logger.info(
            "API %s returned | function=%s | duration=%.1fms",
            layer,
            method_name,
            (perf_counter() - started_at) * 1000,
        )
        return result

    return sync_wrapper


# Work with trace class.
def _trace_class(application_class, layer: str):

    for name, attribute in vars(application_class).items():
        if name.startswith("_"):
            continue
        if isinstance(attribute, staticmethod):
            wrapped = staticmethod(_logged_layer_method(attribute.__func__, layer))
        elif isinstance(attribute, classmethod):
            wrapped = classmethod(_logged_layer_method(attribute.__func__, layer))
        elif callable(attribute):
            wrapped = _logged_layer_method(attribute, layer)
        else:
            continue
        setattr(application_class, name, wrapped)
    return application_class


# Work with trace controller.
def trace_controller(controller_class):

    return _trace_class(controller_class, "controller")


# Work with trace usecase.
def trace_usecase(usecase_class):

    return _trace_class(usecase_class, "usecase")


# Work with trace repository.
def trace_repository(repository_class):

    return _trace_class(repository_class, "repository")


# Handle the logged route.
class LoggedRoute(APIRoute):

    # Get route handler.
    def get_route_handler(self):

        original_handler = super().get_route_handler()
        endpoint_name = f"{self.endpoint.__module__}.{self.endpoint.__qualname__}"

        # Work with logged handler.
        async def logged_handler(request: Request) -> Response:
            started_at = perf_counter()
            logger.info(
                "API request started | %s %s | handler=%s",
                request.method,
                request.url.path,
                endpoint_name,
            )
            try:
                response = await original_handler(request)
            except (HTTPException, RequestValidationError) as exc:
                duration_ms = (perf_counter() - started_at) * 1000
                status_code = (
                    exc.status_code if isinstance(exc, HTTPException) else 422
                )
                logger.info(
                    "API request rejected | %s %s | handler=%s | status=%s | error=%s | duration=%.1fms",
                    request.method,
                    request.url.path,
                    endpoint_name,
                    status_code,
                    exc.detail
                    if isinstance(exc, HTTPException)
                    else "request validation failed",
                    duration_ms,
                )
                raise
            except Exception:
                duration_ms = (perf_counter() - started_at) * 1000
                logger.exception(
                    "API request failed | %s %s | handler=%s | duration=%.1fms",
                    request.method,
                    request.url.path,
                    endpoint_name,
                    duration_ms,
                )
                raise

            duration_ms = (perf_counter() - started_at) * 1000
            logger.info(
                "API request completed | %s %s | handler=%s | status=%s | duration=%.1fms",
                request.method,
                request.url.path,
                endpoint_name,
                response.status_code,
                duration_ms,
            )
            return response

        return logged_handler
