# -*- coding: utf-8 -*-
import datetime
import json
import io
from unittest.mock import patch
from urllib.error import HTTPError
import warnings

import boto3
from botocore.stub import Stubber
from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.test import TestCase, RequestFactory
from jose import jwt as jose_jwt
import pytest
from rest_framework import exceptions

from drftoolbox import authentication


class TestOpenIdJWTAuthentication(authentication.BaseOpenIdJWTAuthentication):
    def authenticate_credentials(self, payload):
        try:
            return get_user_model().objects.get(id=payload.get('user_id'))
        except get_user_model().DoesNotExist:
            return None

    def acceptable_issuers(self):
        return ['issuer']

    def acceptable_audiences(self, payload):
        return ['audience1', 'audience2']


class TestKMSSecretAPISignatureAuthentucation(authentication.BaseKMSSecretAPISignatureAuthentication):
    @classmethod
    def get_aws_kms_arn(cls):
        return 'ARN'

    def get_user(self, api_key):
        if api_key == 'missing':
            return None
        return get_user_model().objects.get(username=api_key)


class JWKSToPublicKeyTests(TestCase):
    def _test_jwks_bytes(self):
        return io.BytesIO(b'''
            {
                "keys": [
                    {
                        "x5c": [
                            "MIIDADCCAeigAwIBAgIJRBuyVkJjKIJHMA0GCSqGSIb3DQEBCwUAMCcxJTAjBgNVBAMTHGV2aWRlbmNlY2FyZS1hbHBoYS5hdXRoMC5jb20wHhcNMTcwMzE0MTg0NzE4WhcNMzAxMTIxMTg0NzE4WjAnMSUwIwYDVQQDExxldmlkZW5jZWNhcmUtYWxwaGEuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4PBE/KDjRoLy/mhU5tgDkpNnahrBsoek9OljqZV2j9zyFIezXURhEI6unljLGxpgpujG+fKbDFa0RDsWuaZaTvr3wKNlqV1N6onQaEule63a5jnaoavU0NvjVBnW5SjKUA7OaazWW3Uwag1b9Y3f9+9au2tDmbKhrNKlSFTIAAAwCcHLMvQivdTyM04aV+CWj+d4F/M63iijuqZ7fEBYzg/vCvtbNYBQWixDq2IYMGjPx5/OMk2NGD0z2wbUV7Yk0XycOfq/CqoJp2M4DDwh85wd+Hkn8QWf62+pC5HEtLk4uELAcsqHMnSnHvDVQjz7rPDPVQMt0CwIpPvsz6TYwwIDAQABoy8wLTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQvOOrvdyidl9TnICqjVIgRcQqD+TANBgkqhkiG9w0BAQsFAAOCAQEA12iZ9hvCZHsOv7yUr7TRcxvfpQXL0v7tcCShU/3UHQ6gBDyvDSk0Vrqx0PcuMnwtkK1szItZdS3kvwST7/189KY14IjAdLK1HASOyIUw1yoMiZlWPdnDvWp+Sp4Qd2LAiM0jjdi3c9MKCQkkpwXDJbtt/krLB/Lxk5S6XNUcZ59TEmYUp2/vLK4OPH3tkKXMwwVtPm7t94I+XdHU4XOkeD/3LuDT1xQYgoOJ+F8vqxdgVZrDf2ZVSvPIIeWImrhe40w9bZlhT21dSwr/h1Kgb/Ijts/+nmpnpSwaCUHEBCVzYEdhZZ6ULbeduL8hnozl3AuDQ8Z7egilssG2VcpDmQ=="
                        ],
                        "kid": "X"
                    }
                ]
            }''')

    @patch('urllib.request.urlopen')
    def test_kid_not_matched(self, mock_urlopen):
        mock_urlopen.return_value = self._test_jwks_bytes()
        key = authentication.jwks_to_public_key('<url-1>', kid='Y')
        assert key is None

    @patch('urllib.request.urlopen')
    def test_missing_required_keys(self, mock_urlopen):
        mock_urlopen.return_value = self._test_jwks_bytes()
        key = authentication.jwks_to_public_key('<url-1>', kid='X', required_keys=['a'])
        assert key is None

    @patch('urllib.request.urlopen')
    def test_kid_matched(self, mock_urlopen):
        mock_urlopen.return_value = self._test_jwks_bytes()
        key = authentication.jwks_to_public_key('<url-2>', kid='X')
        assert key == json.load(self._test_jwks_bytes())['keys'][0]

    @patch('urllib.request.urlopen')
    def test_cache_used(self, mock_urlopen):
        mock_urlopen.return_value = self._test_jwks_bytes()
        for _ in range(2):
            authentication.jwks_to_public_key('<url-3>', kid='X')
        assert mock_urlopen.call_count == 1

    @patch('urllib.request.urlopen')
    def test_non_json_value(self, mock_urlopen):
        mock_urlopen.return_value = io.BytesIO(b'<html></html>')
        key = authentication.jwks_to_public_key('<url-5>')
        assert key is None

    def test_invalid_url_format(self):
        key = authentication.jwks_to_public_key('<url-5>')
        assert key is None

    @patch('urllib.request.urlopen')
    def test_url_not_found(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError('url', '404', 'nf', {}, None)
        key = authentication.jwks_to_public_key('<url-6>')
        assert key is None


class OpenidConfigurationToJWKSURITests(TestCase):
    def _test_openidconf_bytes(self):
        return io.BytesIO(b'''
            {
                "jwks_uri": "https://test-jwks-uri.com"
            }
            ''')

    @patch('urllib.request.urlopen')
    def test_value_found(self, mock_urlopen):
        mock_urlopen.return_value = self._test_openidconf_bytes()
        uri = authentication.openid_configuration_to_jwks_uri('<url-1>')
        assert uri == "https://test-jwks-uri.com"

    @patch('urllib.request.urlopen')
    def test_value_not_found(self, mock_urlopen):
        mock_urlopen.return_value = io.BytesIO(b'{}')
        uri = authentication.openid_configuration_to_jwks_uri('<url-2>')
        assert uri is None

    @patch('urllib.request.urlopen')
    def test_cache_used(self, mock_urlopen):
        mock_urlopen.return_value = self._test_openidconf_bytes()
        for _ in range(2):
            authentication.openid_configuration_to_jwks_uri('<url-3>')
        assert mock_urlopen.call_count == 1

    @patch('urllib.request.urlopen')
    def test_non_json_value(self, mock_urlopen):
        mock_urlopen.return_value = io.BytesIO(b'<html></html>')
        uri = authentication.openid_configuration_to_jwks_uri('<url-4>')
        assert uri is None

    def test_invalid_url_format(self):
        uri = authentication.openid_configuration_to_jwks_uri('<url-5>')
        assert uri is None

    @patch('urllib.request.urlopen')
    def test_url_not_found(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError('url', '404', 'nf', {}, None)
        uri = authentication.openid_configuration_to_jwks_uri('<url-6>')
        assert uri is None


class KMSDecryptedUrlSecretTests(TestCase):
    def _test_decrypted_secret_bytes(self, expires_in=300):
        ts = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)
        return io.BytesIO('''
            {{
                "encrypted_key": "PGtleT4=",
                "expiry": "{}"
            }}
            '''.format(ts.isoformat()).encode())

    def _test_kms_decrypt(self):
        return {
            'KeyId': 'key',
            'ResponseMetadata': {},
            'Plaintext': b'<secret>',
        }

    @patch('urllib.request.urlopen')
    def test_decrypt(self, mock_urlopen):
        client = boto3.client('kms')
        stubber = Stubber(client)
        expected_params = {'CiphertextBlob': b'<key>'}
        stubber.add_response('decrypt', self._test_kms_decrypt(), expected_params)
        stubber.activate()
        mock_urlopen.return_value = self._test_decrypted_secret_bytes()
        secret = authentication.kms_decrypted_url_secret('<url>', client=client)
        assert secret == b'<secret>'

    @patch('urllib.request.urlopen')
    def test_cache_used(self, mock_urlopen):
        client = boto3.client('kms')
        stubber = Stubber(client)
        expected_params = {'CiphertextBlob': b'<key>'}
        stubber.add_response('decrypt', self._test_kms_decrypt(), expected_params)
        stubber.activate()
        mock_urlopen.return_value = self._test_decrypted_secret_bytes()
        for _ in range(2):
            authentication.kms_decrypted_url_secret('<url>', client=client)
        assert mock_urlopen.call_count == 1


class OpenIdJWTAutenticationTests(TestCase):
    def test_wrong_authenticator(self):
        backend = TestOpenIdJWTAuthentication()
        request = RequestFactory().get('/')
        assert backend.authenticate(request) is None
        request = RequestFactory().get('/', HTTP_AUTHORIZATION=b'JWT X')
        assert backend.authenticate(request) is None

    def test_invalid_authorization_header(self):
        backend = TestOpenIdJWTAuthentication()
        request = RequestFactory().get('/', HTTP_AUTHORIZATION=b'Bearer')
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)
        request = RequestFactory().get('/', HTTP_AUTHORIZATION=b'Bearer X Y')
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    def test_bad_payload(self):
        backend = TestOpenIdJWTAuthentication()
        request = RequestFactory().get('/', HTTP_AUTHORIZATION=b'Bearer X')
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    def test_bad_openid_uri(self, mock_openid):
        mock_openid.return_value = None
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({}, 'test', headers={})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) is None

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_bad_jwks_uri(self, mock_jwks, mock_openid):
        mock_jwks.return_value = None
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({}, 'test', headers={})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) is None

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_bad_signature(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'bad'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({'iss': 'issuer', 'aud': 'audience'}, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_invalid_issuer(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({'iss': 'invalid', 'aud': 'audience'}, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) is None

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_invalid_audience(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({'iss': 'issuer', 'aud': 'invalid'}, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) is None

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_invalid_algorithm(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({'iss': 'issuer', 'aud': 'audience'}, 'test', headers={'alg': 'RS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_invalid_user(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({'iss': 'issuer', 'aud': 'audience'}, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) is None

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_valid_user(self, mock_jwks, mock_openid):
        user = get_user_model().objects.create_user('test')
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        payload = {'iss': 'issuer', 'aud': 'audience1', 'user_id': user.id}
        jwt = jose_jwt.encode(payload, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) == (user, payload)
        payload = {'iss': 'issuer', 'aud': 'audience2', 'user_id': user.id}
        jwt = jose_jwt.encode(payload, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) == (user, payload)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_valid_user_audience_deprecation(self, mock_jwks, mock_openid):
        user = get_user_model().objects.create_user('test')
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        backend.acceptable_audience = lambda self: 'audience1'
        payload = {'iss': 'issuer', 'aud': 'audience1', 'user_id': user.id}
        jwt = jose_jwt.encode(payload, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            assert backend.authenticate(request) == (user, payload)
            assert len(w) == 1
            assert w[0].category == DeprecationWarning
        payload = {'iss': 'issuer', 'aud': 'audience2', 'user_id': user.id}
        jwt = jose_jwt.encode(payload, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            assert backend.authenticate(request) is None
            assert len(w) == 1
            assert w[0].category == DeprecationWarning


class BaseKMSSecretAPISignatureAuthenticationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('test')
        self.kms_client = boto3.client('kms', region_name='us-east-1')
        self.stubber = Stubber(self.kms_client)
        self.backend = TestKMSSecretAPISignatureAuthentucation()
        self.backend.client = self.kms_client
        caches['default'].clear()

    def _test_decrypted_key_bytes(self, expires_in=300):
        ts = datetime.datetime.now() + datetime.timedelta(seconds=expires_in)
        return io.BytesIO('''
            {{
                "encrypted_key": "PGtleT4=",
                "expiry": "{}"
            }}
            '''.format(ts.isoformat()).encode())

    def _test_kms_decrypt(self):
        return {
            'KeyId': 'key',
            'ResponseMetadata': {},
            'Plaintext': b'<secret>',
        }

    @patch('drftoolbox.authentication.BaseKMSSecretAPISignatureAuthentication.user_secret')
    @patch('drftoolbox.authentication.BaseKMSSecretAPISignatureAuthentication.encrypted_user_secret')
    def test_fetch_valid_user(self, mock_encrypt, mock_secret):
        mock_encrypt.return_value = 'b2s=', None
        mock_secret.return_value = 'ok'
        data = self.backend.fetch_user_data(self.user.username)
        assert data[0] == self.user
        assert data[1] == 'ok'

    def test_fetch_invalid_user(self):
        data = self.backend.fetch_user_data('invalid')
        assert data is None
        data = self.backend.fetch_user_data('missing')
        assert data is None

    def test_encrypt_user_secret(self):
        self.stubber.add_response('encrypt', {'CiphertextBlob': b'kms-key'})
        self.stubber.activate()
        ttl = datetime.datetime.now() + datetime.timedelta(seconds=5)
        self.backend.cache_timeout = 5
        val = self.backend.encrypted_user_secret(self.user)
        assert val[0] == b'a21zLWtleQ=='
        assert abs(val[1] - ttl) < datetime.timedelta(seconds=1)

    def test_encrypt_user_secret_cache_used(self):
        self.stubber.add_response('encrypt', {'CiphertextBlob': b'kms-key'})
        self.stubber.add_client_error('encrypt', 'should not be reached')
        self.stubber.activate()
        for _ in range(2):
            self.backend.encrypted_user_secret(self.user)

    def test_user_secret(self):
        secret1 = self.backend.user_secret(self.user)
        assert jose_jwt.get_unverified_claims(secret1) == {'user_pk': 1}
        secret2 = self.backend.user_secret(self.user)
        assert secret1 == secret2
        self.user.secret_payload = lambda: {'version': 1}
        secret3 = self.backend.user_secret(self.user)
        assert secret1 != secret3
        assert jose_jwt.get_unverified_claims(secret3) == {'user_pk': 1, 'version': 1}
