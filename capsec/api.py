from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from .analyzer import analyze_pact
from .io import combine_sources, load_pact_sources
from .llm_backend import LLMBackend


def _load_backend() -> LLMBackend | None:
    backend_spec = os.environ.get("CAPSEC_LLM_BACKEND")
    if not backend_spec:
        return None
    if ":" not in backend_spec:
        raise ValueError("CAPSEC_LLM_BACKEND must be in module:Class format.")
    module_name, class_name = backend_spec.split(":", 1)
    module = __import__(module_name, fromlist=[class_name])
    backend_class = getattr(module, class_name)
    return backend_class()


class CapSecHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict, status: int = 200) -> None:
        response = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/analyze":
            self._send_json({"error": "Not found"}, status=404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON"}, status=400)
            return

        code = payload.get("code")
        paths = payload.get("paths") or payload.get("path")
        mode = payload.get("mode", "heuristic")

        if code and paths:
            self._send_json({"error": "Provide either code or paths, not both."}, status=400)
            return

        if code is None and paths is None:
            self._send_json({"error": "Provide code or paths."}, status=400)
            return

        if code is None:
            if isinstance(paths, str):
                paths = [paths]
            sources = load_pact_sources(paths)
            code = combine_sources(sources)

        backend = None
        if mode in {"llm", "hybrid"}:
            try:
                backend = _load_backend()
            except Exception as exc:  # noqa: BLE001
                self._send_json({"error": f"Failed to load LLM backend: {exc}"}, status=400)
                return
            if backend is None:
                self._send_json({"error": "CAPSEC_LLM_BACKEND is required for llm/hybrid mode."}, status=400)
                return

        result = analyze_pact(code, llm_backend=backend, mode=mode)
        self._send_json(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CapSec HTTP API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    server = HTTPServer((args.host, args.port), CapSecHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
