# -*- coding: utf-8 -*-
import logging

import boto3
from botocore.stub import Stubber
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.cache import caches
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from drftoolbox import views, authentication


class KMSSecretAPISignatureAuthentucation(authentication.BaseKMSSecretAPISignatureAuthentication):
    client = boto3.client('kms', region_name='us-east-1')
    cache_timeout = 5

    def get_aws_kms_arn(self):
        return 'ARN'

    def get_user(self, api_key):
        return get_user_model().objects.get(username=api_key)


class UserKMSKeyView(views.BaseUserKMSKeyView):
    def http_sign_class(self):
        return KMSSecretAPISignatureAuthentucation


class BaseUserKMSKeyView(TestCase):
    def setUp(self):
        self.stubber = Stubber(KMSSecretAPISignatureAuthentucation.client)
        caches['default'].clear()

    def test_inactive_user_key(self):
        user = get_user_model().objects.create_user('test', is_active=False)
        req = APIRequestFactory().get('/user-key/{}'.format(user.pk))
        resp = UserKMSKeyView.as_view()(req, pk=user.pk)
        assert resp.status_code == 404

    def test_user_key(self):
        user = get_user_model().objects.create_user('test')
        self.stubber.add_response('encrypt', {'CiphertextBlob': b'kms-key'})
        self.stubber.activate()
        req = APIRequestFactory().get('/user-key/{}'.format(user.pk))
        resp = UserKMSKeyView.as_view()(req, pk=user.pk)
        assert resp.status_code == 200
        assert resp.data['encrypted_key'] is not None
        assert resp.data['expiry'] is not None


class LoggingView(views.RequestLoggingViewMixin, APIView):
    def post(self, request):
        return Response('ok')


class TestRequestLoggingViewMixin():
    def test_obfuscate(self):
        mixin = views.RequestLoggingViewMixin
        val = 'jwt ajwttokenvalue'
        assert mixin.obfuscate(val) == 'jwt aj...'
        val = 's=svalueincookie; t=tvalueincookie'
        assert mixin.obfuscate(val) == 's svalue... t tvalue...'

    def test_log_simple_request(self, caplog):
        req = APIRequestFactory().post('/?a=b', data={'x': 'v'})
        with caplog.at_level(logging.INFO, logger='drftoolbox.views'):
            LoggingView.as_view()(req)
        assert len(caplog.records) == 1
        msg = ' '.join(caplog.text.split())
        assert '"path": "/"' in msg
        assert '"query params": { "a": [ "b" ] }' in msg
        assert '"data": { "x": "v" }' in msg

    def test_log_authorization(self, caplog):
        req = APIRequestFactory().post(
                '/?a=b',
                data={'x': 'v'},
                HTTP_AUTHORIZATION='token abcdef')
        with caplog.at_level(logging.INFO, logger='drftoolbox.views'):
            LoggingView.as_view()(req)
        assert len(caplog.records) == 1
        msg = ' '.join(caplog.text.split())
        assert '"Authorization": "token ..."' in msg

    def test_log_jwt_authorization(self, caplog):
        jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        req = APIRequestFactory().post(
                '/?a=b',
                data={'x': 'v'},
                HTTP_AUTHORIZATION=f'jwt {jwt}')
        with caplog.at_level(logging.INFO, logger='drftoolbox.views'):
            LoggingView.as_view()(req)
        assert len(caplog.records) == 1
        msg = ' '.join(caplog.text.split())
        assert '"jwt_headers": { "alg": "HS256", "typ": "JWT" }' in msg
        assert '"jwt_claims": { "sub": "1234567890", "name": "John Doe", "iat": 1516239022 }' in msg
