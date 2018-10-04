# -*- coding: utf-8 -*-
"""
    drftoolbox.middleware
    ~~~~~~~~~~~~~~~~~~~~~

    This module defines middleware classes useful for API services

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import os


class XSSJsonMiddleware(object):
    """
    Use this Django middleware class to convert all `'<', '>' and '&'` chars
    in the content response to their respective unicode escape sequences.  This
    mitigates any attempt for a malicious user to create an XSS attack by saving
    JS scripts.

    This middleware will only be executed if a) the response is not streaming
    b) the response content is JSON and c) the middleware has not been disabled
    in the environment.
    """
    ESCAPES = {
        ord('>'): '\\u003E',
        ord('<'): '\\u003C',
        ord('&'): '\\u0026',
    }
    ENABLED_ENV = 'DRF-XSS-JSON-ESCAPE'

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        resp = self.get_response(request)
        if hasattr(resp, 'streaming_content'):
            # the response is streaming, and not supported by this middleware
            return resp
        if resp.get('Content-Type') != 'application/json':
            # this middleware only supports JSON responses
            return resp
        enabled = os.environ.get(self.ENABLED_ENV, 'true')
        if enabled.lower() not in ['true', 't', '1', 'yes', 'y']:
            # middleware is disabled in the ENV
            return resp
        escaped = resp.content.decode().translate(self.ESCAPES)
        resp.content = escaped.encode()
        return resp
