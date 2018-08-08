# -*- coding: utf-8 -*-
import datetime

import boto3
from botocore.stub import Stubber
from django.test import TestCase
from django.contrib.auth import get_user_model
import pytest
from rest_framework import views

from drftoolbox import serializers, authentication


class TestKMSSecretAPISignatureAuthentucation(authentication.BaseKMSSecretAPISignatureAuthentication):
    client = boto3.client('kms', region_name='us-east-1')
    cache_timeout = None

    def get_aws_kms_arn(self):
        return 'ARN'

    def get_user(self, api_key):
        return get_user_model().objects.get(username=api_key)


class UserKMSKeySerializerTests(TestCase):
    def setUp(self):
        self.view = views.APIView()
        self.view.http_sign_class = lambda: TestKMSSecretAPISignatureAuthentucation
        self.serializer = serializers.UserKMSKeySerializer(context={'view': self.view})
        self.stubber = Stubber(TestKMSSecretAPISignatureAuthentucation.client)

    def test_no_expiry(self):
        user = get_user_model().objects.create_user('test')
        self.stubber.add_response('encrypt', {'CiphertextBlob': b'kms-key'})
        self.stubber.activate()
        data = self.serializer.to_representation(user)
        assert data['encrypted_key'] == b'a21zLWtleQ=='
        assert data['expiry'] is None

    def test_expiry(self):
        user = get_user_model().objects.create_user('test')
        self.stubber.add_response('encrypt', {'CiphertextBlob': b'kms-key'})
        self.stubber.activate()
        TestKMSSecretAPISignatureAuthentucation.cache_timeout = 5
        data = self.serializer.to_representation(user)
        assert data['encrypted_key'] == b'a21zLWtleQ=='
        assert data['expiry'] is not None
        ttl = datetime.datetime.now() + datetime.timedelta(seconds=5)
        assert abs(data['expiry'] - ttl) < datetime.timedelta(seconds=1)

    def test_view_with_no_http_sign_class(self):
        user = get_user_model().objects.create_user('test')
        serializer = serializers.UserKMSKeySerializer(context={'view': views.APIView()})
        with pytest.raises(AssertionError):
            serializer.to_representation(user)
