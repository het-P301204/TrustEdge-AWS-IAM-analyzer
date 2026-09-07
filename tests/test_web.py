"""Tests for the optional local viewer.

The viewer is a convenience, not the product, so these tests cover the
contract that matters: it analyses what you give it, it refuses what it cannot
parse with a useful message instead of a stack trace, and it does not accept
unbounded input.
"""

from __future__ import annotations

import http.client
import json
import threading

import pytest

from conftest import fixture_path
from trustedge import web


@pytest.fixture(scope="module")
def server():
    instance = web.build_server(host="127.0.0.1", port=0, quiet=True)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=5)


@pytest.fixture
def client(server):
    host, port = server.server_address[0], server.server_address[1]
    connection = http.client.HTTPConnection(host, port, timeout=15)
    try:
        yield connection
    finally:
        connection.close()


def get(client, path):
    client.request("GET", path)
    response = client.getresponse()
    return response.status, response.read().decode("utf-8"), response


def post(client, path, body, content_type="application/json"):
    encoded = body.encode("utf-8") if isinstance(body, str) else body
    client.request(
        "POST",
        path,
        body=encoded,
        headers={"Content-Type": content_type, "Content-Length": str(len(encoded))},
    )
    response = client.getresponse()
    return response.status, response.read().decode("utf-8")


class TestRoutes:
    def test_index_serves_the_upload_page(self, client):
        status, body, response = get(client, "/")
        assert status == 200
        assert "text/html" in response.getheader("Content-Type")
        assert "Drop an IAM export here" in body
        assert "trustedgeWireFilters" in body

    def test_index_page_reuses_the_report_stylesheet(self, client):
        _, body, _ = get(client, "/")
        assert "details.finding" in body

    def test_health_endpoint(self, client):
        status, body, _ = get(client, "/healthz")
        assert status == 200
        assert json.loads(body)["ok"] is True

    def test_unknown_path_is_a_json_404(self, client):
        status, body, _ = get(client, "/nope")
        assert status == 404
        assert json.loads(body)["ok"] is False

    def test_post_to_an_unknown_path_is_a_404(self, client):
        status, body = post(client, "/nope", "{}")
        assert status == 404
        assert json.loads(body)["ok"] is False

    def test_security_headers_are_set(self, client):
        _, _, response = get(client, "/")
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("Referrer-Policy") == "no-referrer"
        assert "default-src 'none'" in response.getheader("Content-Security-Policy")


class TestAnalyzeEndpoint:
    def test_analyses_a_native_export(self, client):
        with open(fixture_path("sample-account.json"), "r", encoding="utf-8") as handle:
            body = handle.read()
        status, response_body = post(client, "/api/analyze", body)
        assert status == 200
        payload = json.loads(response_body)
        assert payload["ok"] is True
        assert payload["report"]["summary"]["roles_analyzed"] >= 20
        assert "<details class='finding'" in payload["html"]

    def test_returns_a_fragment_not_a_whole_document(self, client):
        with open(fixture_path("minimal-export.json"), "r", encoding="utf-8") as handle:
            body = handle.read()
        _, response_body = post(client, "/api/analyze", body)
        html = json.loads(response_body)["html"]
        assert "<!DOCTYPE" not in html
        assert "<header>" in html

    def test_analyses_authorization_details_output(self, client):
        with open(
            fixture_path("authorization-details-sample.json"), "r", encoding="utf-8"
        ) as handle:
            body = handle.read()
        status, response_body = post(client, "/api/analyze", body)
        assert status == 200
        assert json.loads(response_body)["report"]["summary"]["roles_analyzed"] >= 1

    def test_include_internal_query_parameter_is_honoured(self, client):
        with open(fixture_path("sample-account.json"), "r", encoding="utf-8") as handle:
            body = handle.read()
        _, without = post(client, "/api/analyze?include_internal=0", body)
        _, with_internal = post(client, "/api/analyze?include_internal=1", body)
        assert (
            json.loads(with_internal)["report"]["summary"]["findings_total"]
            > json.loads(without)["report"]["summary"]["findings_total"]
        )

    def test_invalid_json_gets_a_readable_error(self, client):
        status, body = post(client, "/api/analyze", "{not json")
        assert status == 400
        payload = json.loads(body)
        assert payload["ok"] is False
        assert "Not valid JSON" in payload["error"]

    def test_a_json_array_gets_the_parser_error_message(self, client):
        status, body = post(client, "/api/analyze", "[]")
        assert status == 400
        assert "expected an object" in json.loads(body)["error"]

    def test_empty_body_is_rejected(self, client):
        client.request(
            "POST",
            "/api/analyze",
            body=b"",
            headers={"Content-Type": "application/json", "Content-Length": "0"},
        )
        response = client.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 400
        assert "Empty request body" in json.loads(body)["error"]

    def test_oversized_body_is_refused_without_reading_it(self, client):
        client.request(
            "POST",
            "/api/analyze",
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(web.MAX_BODY_BYTES + 1),
            },
        )
        response = client.getresponse()
        body = response.read().decode("utf-8")
        assert response.status == 413
        assert "too large" in json.loads(body)["error"]

    def test_a_malformed_export_still_produces_a_report(self, client):
        with open(
            fixture_path("malformed-export.json"), "r", encoding="utf-8"
        ) as handle:
            body = handle.read()
        status, response_body = post(client, "/api/analyze", body)
        assert status == 200
        payload = json.loads(response_body)
        assert payload["report"]["input_issues"]


class TestServerConfiguration:
    def test_body_limit_is_bounded(self):
        assert 0 < web.MAX_BODY_BYTES <= 64 * 1024 * 1024

    def test_build_server_binds_where_asked(self):
        instance = web.build_server(host="127.0.0.1", port=0, quiet=True)
        try:
            assert instance.server_address[0] == "127.0.0.1"
            assert instance.server_address[1] > 0
        finally:
            instance.server_close()

    def test_quiet_flag_reaches_the_handler(self):
        instance = web.build_server(host="127.0.0.1", port=0, quiet=True)
        try:
            assert instance.RequestHandlerClass.quiet is True
        finally:
            instance.server_close()
