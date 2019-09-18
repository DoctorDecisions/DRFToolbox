# -*- coding: utf-8 -*-
"""
    drftoolbox.views
    ~~~~~~~~~~~~~~~~

    This module defines view classes used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import functools
import json
import logging
import re

from django.contrib.auth import get_user_model
from rest_framework import generics
from jose import jwt as jose_jwt, exceptions as jose_exceptions

from drftoolbox.serializers import UserKMSKeySerializer

LOGGER = logging.getLogger(__name__)


class BaseUserKMSKeyView(generics.RetrieveAPIView):
    queryset = get_user_model().objects.filter(is_active=True)
    serializer_class = UserKMSKeySerializer

    def http_sign_class(self):
        raise NotImplementedError


class RequestLoggingViewMixin(object):
    REQUEST_LOGGING_LOGGER = LOGGER
    REQUEST_LOGGING_LEVEL = logging.INFO
    REQUEST_LOGGING_OBFUSCATE_PATTERN = re.compile(r'.*(authorization|cookie)$', re.I)

    @classmethod
    def obfuscate(cls, value):
        result = []
        for section in str(value).split('; '):
            # try handling the value as a cookie, and if so see if we can
            # only obfuscate the value parts of that cookie, however if not
            # a cookie just fall back to obfuscating everything after the
            # first 6 chars
            parts = section.split('=', 1)
            k = parts[0] if len(parts) > 1 else ''
            v = parts[-1]
            result.append(f'{k} {v[:6]}...'.strip())
        return ' '.join(result)

    @classmethod
    def request_logging(cls, request):
        """
        utility method to log the details of a request
        """
        log = functools.partial(cls.REQUEST_LOGGING_LOGGER.log, cls.REQUEST_LOGGING_LEVEL)
        pattern = cls.REQUEST_LOGGING_OBFUSCATE_PATTERN
        data, headers = {}, {}

        for k, v in request.data.items():
            if pattern.match(k):
                v = cls.obfuscate(v)
            data[k] = v
        for k, v in request._request.headers.items():  # pylint: disable=protected-access
            if pattern.match(k):
                try:
                    token = v.split()[-1]
                    v = {
                        'jwt_headers': jose_jwt.get_unverified_header(token),
                        'jwt_claims': jose_jwt.get_unverified_claims(token),
                    }
                except jose_exceptions.JOSEError:
                    v = cls.obfuscate(v)
            headers[k] = v
        msg = {
            'path': request._request.path,  # pylint: disable=protected-access
            'query params': dict(request.query_params),
            'data': data,
            'headers': headers,
        }
        log(f'REQUEST => {json.dumps(msg, indent=2)}')

    def initialize_request(self, *args, **kwargs):
        request = super().initialize_request(*args, **kwargs)
        self.request_logging(request)
        return request
