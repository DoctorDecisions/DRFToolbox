# -*- coding: utf-8 -*-
"""
    drftoolbox.authentication
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    This module defines authentication classes used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import base64
import logging
import json
import urllib.request
import urllib.error
import warnings

import boto3
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.utils.crypto import get_random_string
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
from jose import jwt as jose_jwt, exceptions as jose_exceptions
from rest_framework import authentication, exceptions
from rest_framework.settings import api_settings
from rest_framework_httpsignature.authentication import SignatureAuthentication

LOGGER = logging.getLogger(__name__)


def jwks_to_public_key(url, kid=None, required_keys=None, timeout=None):
    """
    Given a URL linking to a public JSON Web Key Set (JWKS), return the public
    key defined, by parsing the certificate.
    """
    required_keys = set(required_keys or [])
    key = 'jwks-url:{}:{}'.format(url, kid)
    value = cache.get(key)
    if value is None:
        LOGGER.debug('loading JWKS')
        try:
            resp = urllib.request.urlopen(url)
            jwks = json.loads(resp.read().decode())
            keys = jwks['keys']
            value = None
            for public_key in keys:
                if not set(public_key.keys()).issuperset(required_keys):
                    continue
                if not kid or kid == public_key['kid']:
                    value = public_key
                    break
            if value is None:
                return None
        except (ValueError, urllib.error.HTTPError):
            return None
        cache.set(key, value, timeout)
    return value


def openid_configuration_to_jwks_uri(url, timeout=None):
    """
    Given a URL linking to a public OpenId Configuration, return the URI value
    of the `jwks_uri` key.
    """
    key = 'openidconf-url:{}'.format(url)
    value = cache.get(key)
    if value is None:
        LOGGER.debug('loading openid configuration')
        try:
            resp = urllib.request.urlopen(url)
            conf = json.loads(resp.read().decode())
            value = conf.get('jwks_uri')
            cache.set(key, value, timeout)
        except (ValueError, urllib.error.HTTPError):
            return None
    return value


def kms_decrypted_url_key(url, client=None, timeout=None):
    """
    Given a URL linking to a encrypted KMS key, return the decrypted value by
    downloading the key, and using AWS KMS to decrypt
    """
    key = 'kmskey-url:{}'.format(url)
    value = cache.get(key)
    if value is None:
        LOGGER.debug('loading KMS key')
        resp = urllib.request.urlopen(url)
        data = json.loads(resp.read().decode())
        encrypted_key = base64.b64decode(data['encrypted_key'])
        expiry = data.get('expiry')
        if expiry:
            expires_at = dateparse.parse_datetime(expiry)
            if timezone.is_naive(expires_at):
                expires_at = timezone.make_aware(expires_at)
            timeout = (expires_at - timezone.now()).seconds
        client = client or boto3.client('kms')
        value = client.decrypt(CiphertextBlob=encrypted_key)['Plaintext']
        cache.set(key, value, timeout)
    return value


class BaseOpenIdJWTAuthentication(authentication.BaseAuthentication):
    """
    Use this base class to implement a OpenID configuration based JWT authentication
    module.   Basically this is just a JWT authenticator that assumes an openid
    configuration JSON object can be publicly found using the default URL format of
    `<issuer>.well-known/openid-configuration` (the exact location can be overridden).

    Clients should authenticate by passing an JWT token in the "Authorization"
    HTTP header, prepended with "Bearer". For example:

        Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    auth_header_prefix = 'Bearer'
    www_authenticate_realm = 'api'
    cache_timeout = 60 * 5  # 5 minutes
    jwks_required_keys = ['kid', 'kty']

    def authenticate_credentials(self, payload):
        """
        All implementations must override this method to return a User instance,
        if a User can be identified within the payload or None, if no User exists.
        """
        raise NotImplementedError

    def acceptable_issuers(self):
        """
        All implementations must override this method and return at least one
        acceptable issuer
        """
        raise NotImplementedError

    def acceptable_audiences(self, payload):
        return []

    def openid_configuration_url(self, iss):
        return '{}.well-known/openid-configuration'.format(iss)

    def get_jwt_value(self, request):
        """
        Returns the token string for a request object, if properly formatted.
        """
        auth = authentication.get_authorization_header(request).split()
        if not auth:
            return None
        if smart_text(auth[0].lower()) != self.auth_header_prefix.lower():
            return None
        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]

    def get_public_key(self, issuer, kid=None):
        """
        Given an issuer, return the JWKS public key by first looking up the
        JWKS uri via the OpenID Configuration, then finding the matching
        public key in the JWKS spec
        """
        config_url = self.openid_configuration_url(issuer)
        jwks_uri = openid_configuration_to_jwks_uri(config_url, timeout=self.cache_timeout)
        if jwks_uri is None:
            LOGGER.debug('invalid issuer openid configuration: {}'.format(config_url))
            return None
        key = jwks_to_public_key(url=jwks_uri, kid=kid,
                required_keys=self.jwks_required_keys, timeout=self.cache_timeout)
        if key is None:
            LOGGER.debug('invalid issuer JWKS URI: {}'.format(jwks_uri))
            return None
        return key

    def decode_handler(self, token):
        """
        Decode the JWT, if the issuer and audience within are matches for this
        class, otherwise raise a JWTMismatchClaimException
        """
        header = jose_jwt.get_unverified_header(token)
        claims = jose_jwt.get_unverified_claims(token)
        issuers = self.acceptable_issuers()
        audiences = self.acceptable_audiences(claims)
        if hasattr(self, 'acceptable_audience'):
            msg = (
                '"acceptable_audience()" is deprecated, '
                'please update {} to use "acceptable_audiences()"'
            ).format(type(self).__name__)
            warnings.warn(msg, DeprecationWarning)
            audiences = [getattr(self, 'acceptable_audience')(claims),]
        key = self.get_public_key(claims.get('iss'), kid=header.get('kid'))
        if key is None:
            raise jose_exceptions.JWTClaimsError('missing public key')
        if not audiences:
            audiences = [None,]
        for idx, aud in enumerate(audiences, start=1):
            # is possible to have more than 1 acceptable audience per issuer
            # thus we should attempt to decode with each possible audience
            # if a ClaimError is raised, move on to the next, however when we
            # have exhausted all of our audiences, pass the ClaimError on to
            # the caller
            try:
                return jose_jwt.decode(
                    token,
                    key,
                    algorithms=[header.get('alg'),],
                    issuer=issuers,
                    audience=aud,
                    options={'verify_aud': (aud is not None)},
                )
            except jose_exceptions.JWTClaimsError:
                if idx == len(audiences):
                    raise


    def authenticate(self, request):
        """
        Returns a two-tuple of User and JWT payload if a valid signature has
        been supplied using JWT-based authentication and the issuer and
        audience is a match for this class, Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = self.decode_handler(jwt_value)
        except jose_exceptions.JWTClaimsError:
            # issuer and/or audience didn't match, move on to the next
            # authentication module
            return None
        except jose_exceptions.JOSEError as exc:
            # for a problem with the token's validity, raise a 401
            raise exceptions.AuthenticationFailed(exc.args[0])

        user = self.authenticate_credentials(payload)

        return user and (user, payload)

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(self.auth_header_prefix, self.www_authenticate_realm)


class BaseKMSSecretAPISignatureAuthentication(SignatureAuthentication):
    """
    DRF Authentication backend for HTTP signatures based on
    https://github.com/etoccalino/django-rest-framework-httpsignature

    Authorization: Signature keyId="<user-uid>",algorithm="<algorithm>",headers="<header1> <header2>",signature="<signature>"
     - `keyId` is a User's primary key as a string
     - `algorithm` must be one of the following: rsa-sha1, rsa-sha256,
        rsa-sha512, hmac-sha1, hmac-sha256, hmac-sha512.  "hmac-sha256" is the
        inferred default value if not specified.
     - `headers` is a space-delimited list of headers which were signed. A
        default value of "date" is inferred if none are specified.
        "(request-target)" is a valid header value.
     - `signature` is a Base64-encoded signature of the header values using
        the algorithm specified in `algorithm`

    Example Python implementation using `httpsig` and `requests`:
        import json
        import requests
        from httpsig.requests_auth import HTTPSignatureAuth
        auth = HTTPSignatureAuth(key_id='<user-pk>', secret=b'<user-secret>')
        resp = requests.get('https://api.example.com/endpoint', auth=auth)
    """
    cache_timeout = 60 * 5  # 5 minutes

    @classmethod
    def get_aws_kms_arn(cls):
        raise NotImplementedError

    def get_user(self, api_key):
        raise NotImplementedError

    def fetch_user_data(self, api_key):
        try:
            user = self.get_user(api_key)
            if user is not None:
                secret = kms_encrypted_user_key(
                    arn=self.get_aws_kms_arn(),
                    user=user,
                    timeout=self.cache_timeout)
                return user, secret
        except (ObjectDoesNotExist, ValueError):
            pass
        return None
