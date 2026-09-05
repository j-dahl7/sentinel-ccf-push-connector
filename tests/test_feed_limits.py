"""Bounded synthetic HTTP responses; never authenticate or ingest tenant data."""
import importlib.util
import json
from pathlib import Path
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('bounded_sender', ROOT / 'scripts/Send-ThreatIntel.py')
SENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SENDER)


class Body:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def read1(self, size, decode_content=False):
        return next(self.chunks, b'')


class Response:
    def __init__(self, chunks, headers=None, status=200):
        self.raw = Body(chunks)
        self.headers = headers or {}
        self.status_code = status
        self.closed = False

    def close(self):
        self.closed = True


def row(**changes):
    return {'ip_address': '192.0.2.10', 'port': 443, 'malware': 'Fixture', **changes}


class FeedLimitTests(unittest.TestCase):
    def test_valid_split_response_and_explicit_transport_boundary(self):
        encoded = json.dumps([row()]).encode()
        response = Response([encoded[:13], encoded[13:]])
        with patch.object(SENDER.requests, 'get', return_value=response) as get:
            self.assertEqual(SENDER.fetch_indicators(), [row()])
        self.assertTrue(response.closed)
        self.assertEqual(get.call_args.args, (SENDER.FEODO_URL,))
        self.assertTrue(get.call_args.kwargs['stream'])
        self.assertFalse(get.call_args.kwargs['allow_redirects'])
        self.assertEqual(get.call_args.kwargs['headers']['Accept-Encoding'], 'identity')
        self.assertEqual(get.call_args.kwargs['timeout'], (10, 10))

    def test_declared_and_streamed_overflow_close_without_parsing_prefix(self):
        cases = [Response([b'[]'], {'Content-Length': '101'}),
                 Response([b'[' + b' ' * 100, b']']),
                 Response([b'[]'], {'Content-Length': '-1'}),
                 Response([b'[]'], {'Content-Length': 'not-a-number'})]
        for response in cases:
            with self.subTest(headers=response.headers), patch.object(SENDER, 'MAX_FEED_BYTES', 100), patch.object(SENDER.requests, 'get', return_value=response):
                with self.assertRaises(ValueError):
                    SENDER.fetch_indicators()
                self.assertTrue(response.closed)

    def test_redirect_compression_and_missing_list_are_rejected(self):
        for response in [Response([b'[]'], status=302), Response([b'[]'], {'Content-Encoding': 'gzip'}), Response([b'{}'])]:
            with self.subTest(status=response.status_code, headers=response.headers), patch.object(SENDER.requests, 'get', return_value=response):
                with self.assertRaises(ValueError):
                    SENDER.fetch_indicators()
                self.assertTrue(response.closed)

    def test_whole_feed_count_and_field_overflow_precede_authentication_and_ingestion(self):
        env = {'CCF_TENANT_ID': 'fixture-tenant', 'CCF_CLIENT_ID': 'fixture-client', 'CCF_CLIENT_SECRET': 'inert-fixture',
               'CCF_DCE_URI': 'https://fixture.ingest.monitor.azure.com', 'CCF_DCR_ID': 'dcr-fixture'}
        cases = [[row(), row(), row()], [row(), row(malware='x' * 129)],
                 [row(), row(country='界' * 3)], [row(), row(status={'nested': 'bad'})]]
        for indicators in cases:
            response = Response([json.dumps(indicators).encode()])
            with self.subTest(indicators=len(indicators)), patch.dict(SENDER.os.environ, env), patch.object(SENDER, 'MAX_INDICATORS', 2), patch.object(SENDER.requests, 'get', return_value=response), patch.object(SENDER, 'get_oauth_token') as token, patch.object(SENDER, 'send_batch') as send:
                with self.assertRaises(ValueError):
                    SENDER.main()
                token.assert_not_called()
                send.assert_not_called()
                self.assertTrue(response.closed)

    def test_direct_transform_and_send_cannot_bypass_limits(self):
        with self.assertRaises(ValueError):
            SENDER.transform([row(malware='x' * 129)])
        with patch.object(SENDER.requests, 'post') as post:
            for records in [[row()] * 101, [{'malware': 'x' * (512 * 1024)}]]:
                with self.assertRaises(ValueError):
                    SENDER.send_batch(records, 'https://fixture.ingest.monitor.azure.com', 'dcr-fixture', 'Custom-Feed', 'inert')
            post.assert_not_called()

    def test_keepalive_trickle_exceeds_body_budget_on_real_local_stream(self):
        class Trickle(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '1000')
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b' ')
                        self.wfile.flush()
                        time.sleep(0.03)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Trickle)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        original_get = SENDER.requests.get

        def local_get(url, **kwargs):
            self.assertEqual(url, SENDER.FEODO_URL)
            return original_get(f'http://127.0.0.1:{server.server_port}/', **kwargs)

        start = time.monotonic()
        try:
            with patch.object(SENDER.requests, 'get', side_effect=local_get), patch.object(SENDER, 'FEED_BODY_SECONDS', 0.12):
                with self.assertRaises(TimeoutError):
                    SENDER.fetch_indicators()
            self.assertLess(time.monotonic() - start, 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
