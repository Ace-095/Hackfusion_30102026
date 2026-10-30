"""Synthetic target: an in-process HTTPX handler, never a network service."""
import json
from dataclasses import dataclass

import httpx


@dataclass
class FixtureTarget:
    # These knobs model target behavior for tests, not verdicts. The public API
    # always uses the default fixture; only Python tests construct alternatives.
    attacker_access: str = "disclose"  # disclose, deny, unauthorized, not_found, metadata, redirect
    bob_login: bool = True
    owner_sees_canary: bool = True
    canary: str = "synthetic-bob-private-canary"
    cross_list_leak: bool = False
    alice_item_missing: bool = False
    auth_behavior: str = "reject"  # reject, bypass, empty, redirect

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/login":
            data = json.loads(request.content)
            account = data.get("account")
            if account == "bob" and not self.bob_login:
                return httpx.Response(401, json={"error": "unavailable"})
            if account in {"alice", "bob"}:
                return httpx.Response(200, json={"token": f"fixture-token-{account}"})
            return httpx.Response(401)
        token = request.headers.get("Authorization", "")
        actor = {"Bearer fixture-token-alice": "alice", "Bearer fixture-token-bob": "bob"}.get(token)
        if request.method == "GET" and request.url.path == "/items":
            if actor is None:
                return httpx.Response(401)
            if actor == "alice":
                items = [] if self.alice_item_missing else [{"id": "alice-item", "owner": "alice"}]
                if self.cross_list_leak:
                    items.append({"id": "bob-item", "owner": "bob"})
                return httpx.Response(200, json=items)
            return httpx.Response(200, json=[{"id": "bob-item", "owner": "bob"}])
        if request.method == "GET" and request.url.path == "/items/alice-item":
            if actor == "alice" or (actor is None and self.auth_behavior == "bypass"):
                return httpx.Response(200, json={"id": "alice-item", "owner": "alice", "private_note": "synthetic-alice-private-note"})
            if actor is None and self.auth_behavior == "empty":
                return httpx.Response(200, json={})
            if actor is None and self.auth_behavior == "redirect":
                return httpx.Response(302, headers={"Location": "https://elsewhere.invalid"})
            return httpx.Response(401)
        if request.method == "GET" and request.url.path == "/items/bob-item":
            if actor == "bob":
                value = self.canary if self.owner_sees_canary else "different-value"
                return httpx.Response(200, json={"id": "bob-item", "owner": "bob", "private_note": value})
            if actor == "alice":
                if self.attacker_access == "deny":
                    return httpx.Response(403, json={"error": "forbidden"})
                if self.attacker_access == "unauthorized":
                    return httpx.Response(401, json={"error": "token rejected"})
                if self.attacker_access == "not_found":
                    return httpx.Response(404, json={"error": "not found"})
                if self.attacker_access == "redirect":
                    return httpx.Response(302, headers={"Location": "https://elsewhere.invalid"})
                if self.attacker_access == "metadata":
                    return httpx.Response(200, json={"id": "bob-item"})
                if self.attacker_access == "disclose":
                    return httpx.Response(200, json={"id": "bob-item", "owner": "bob", "private_note": self.canary})
            return httpx.Response(401)
        return httpx.Response(404)
