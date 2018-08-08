# -*- coding: utf-8 -*-
import boto3
from botocore.stub import Stubber
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.cache import caches
from rest_framework.test import APIRequestFactory

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
