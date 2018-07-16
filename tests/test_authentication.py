# -*- coding: utf-8 -*-
import json
import io
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory
from jose import jwt as jose_jwt
import pytest
from rest_framework import views, serializers, exceptions
from rest_framework.settings import api_settings

from drftoolbox import authentication


class TestOpenIdJWTAuthentication(authentication.BaseOpenIdJWTAuthentication):
    def authenticate_credentials(self, payload):
        try:
            return get_user_model().objects.get(id=payload.get('user_id'))
        except get_user_model().DoesNotExist:
            return None

    def acceptable_issuers(self):
        return ['issuer']

    def acceptable_audience(self, payload):
        return 'audience'


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
        with pytest.raises(KeyError):
            authentication.jwks_to_public_key('<url-1>', kid='Y')

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
    def test_bad_url(self, mock_urlopen):
        mock_urlopen.return_value = io.BytesIO(b'<html></html>')
        uri = authentication.openid_configuration_to_jwks_uri('<url-4>')
        assert uri is None


class OpenIdJWTAutenticationTests(TestCase):
    def test_invalid_jwt(self):
        backend = TestOpenIdJWTAuthentication()
        request = RequestFactory().get('/')
        assert backend.authenticate(request) is None
        request = RequestFactory().get('/', HTTP_AUTHORIZATION=b'JWT X')
        assert backend.authenticate(request) is None
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
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_bad_jwks_uri(self, mock_jwks, mock_openid):
        mock_jwks.return_value = None
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({}, 'test', headers={})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_bad_signature(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'bad'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({}, 'test', headers={})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_invalid_issuer(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({'iss': 'invalid'}, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

    @patch('drftoolbox.authentication.openid_configuration_to_jwks_uri')
    @patch('drftoolbox.authentication.jwks_to_public_key')
    def test_invalid_audience(self, mock_jwks, mock_openid):
        mock_jwks.return_value = 'test'
        mock_openid.return_value = '<url>'
        backend = TestOpenIdJWTAuthentication()
        jwt = jose_jwt.encode({'iss': 'issuer', 'aud': 'invalid'}, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        with pytest.raises(exceptions.AuthenticationFailed):
            backend.authenticate(request)

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
        payload = {'iss': 'issuer', 'aud': 'audience', 'user_id': user.id}
        jwt = jose_jwt.encode(payload, 'test', headers={'alg': 'HS256'})
        request = RequestFactory().get('/', HTTP_AUTHORIZATION='Bearer {}'.format(jwt).encode())
        assert backend.authenticate(request) == (user, payload)
