# -*- coding: utf-8 -*-
from unittest.mock import patch

from django.test import TestCase, RequestFactory
from django.http import HttpResponse, StreamingHttpResponse

from drftoolbox import middleware


class XSSJsonMiddlewareTests(TestCase):
    def setUp(self):
        self.req = RequestFactory().get('/')
        self.enabled_key = middleware.XSSJsonMiddleware.ENABLED_ENV

    def test_nothing_to_escape(self):
        get_resp = lambda r: HttpResponse(
            content_type='application/json', content=b'{"k": "test"}')
        mid = middleware.XSSJsonMiddleware(get_resp)
        resp = mid(self.req)
        assert resp.content == b'{"k": "test"}'

    def test_non_json_content(self):
        get_resp = lambda r: HttpResponse(
            content_type='text/html', content=b'<b>test</b>')
        mid = middleware.XSSJsonMiddleware(get_resp)
        resp = mid(self.req)
        assert resp.content == b'<b>test</b>'

    def test_escape_html(self):
        get_resp = lambda r: HttpResponse(
            content_type='application/json', content=b'{"k": "<b>test</b>"}')
        mid = middleware.XSSJsonMiddleware(get_resp)
        resp = mid(self.req)
        assert resp.content == b'{"k": "\\u003Cb\\u003Etest\\u003C/b\\u003E"}'

    def test_escape_ampersand(self):
        get_resp = lambda r: HttpResponse(
            content_type='application/json', content=b'{"k": "t&j"}')
        mid = middleware.XSSJsonMiddleware(get_resp)
        resp = mid(self.req)
        assert resp.content == b'{"k": "t\\u0026j"}'

    def test_disabled(self):
        get_resp = lambda r: HttpResponse(
            content_type='application/json', content=b'{"k": "t&j"}')
        mid = middleware.XSSJsonMiddleware(get_resp)
        with patch.dict('os.environ', {self.enabled_key: 'false'}):
            resp = mid(self.req)
            assert resp.content == b'{"k": "t&j"}'

    def test_enabled(self):
        get_resp = lambda r: HttpResponse(
            content_type='application/json', content=b'{"k": "t&j"}')
        mid = middleware.XSSJsonMiddleware(get_resp)
        with patch.dict('os.environ', {self.enabled_key: 'T'}):
            resp = mid(self.req)
            assert resp.content == b'{"k": "t\\u0026j"}'

    def test_streaming_content(self):
        get_resp = lambda r: StreamingHttpResponse(
            content_type='application/json',
            streaming_content=(x for x in [b'{"k": "t&j"}']))
        mid = middleware.XSSJsonMiddleware(get_resp)
        resp = mid(self.req)
        assert b''.join(resp.streaming_content) == b'{"k": "t&j"}'
