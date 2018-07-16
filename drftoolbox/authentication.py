# -*- coding: utf-8 -*-
"""
    drftoolbox.authentication
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    This module defines authentication classes used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import logging
import json
import urllib.request

from django.core.cache import cache
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
from jose import jwt as jose_jwt, exceptions as jose_exceptions
from rest_framework import authentication, exceptions
from rest_framework.settings import api_settings

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
            raise KeyError('matching kid not found: {}'.format(kid))
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
        resp = urllib.request.urlopen(url)
        try:
            conf = json.loads(resp.read().decode())
            value = conf.get('jwks_uri')
            cache.set(key, value, timeout)
        except ValueError:
            return None
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
    timeout = 30
    jwks_required_keys = ['kid', 'kty']

    def authenticate_credentials(self, payload):
        """
        All implementations must override this method to return a User instance,
        if a User can be identified within the payload or None, if no User exists.
        """
        raise NotImplementedError

    def acceptable_issuers(self):
        return None

    def acceptable_audience(self, payload):
        return None

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

    def decode_handler(self, token):
        header = jose_jwt.get_unverified_header(token)
        claims = jose_jwt.get_unverified_claims(token)
        config_url = self.openid_configuration_url(claims.get('iss'))
        jwks_uri = openid_configuration_to_jwks_uri(config_url, timeout=self.timeout)
        if jwks_uri is None:
            msg = _('Invalid issuer openid configuration')
            raise exceptions.AuthenticationFailed(msg)
        key = jwks_to_public_key(url=jwks_uri, kid=header.get('kid'),
                required_keys=self.jwks_required_keys, timeout=self.timeout)
        if key is None:
            msg = _('Invalid issuer JWKS URI')
            raise exceptions.AuthenticationFailed(msg)
        return jose_jwt.decode(
            token,
            key,
            algorithms=[header.get('alg'),],
            issuer=self.acceptable_issuers(),
            audience=self.acceptable_audience(claims),
        )

    def authenticate(self, request):
        """
        Returns a two-tuple of User and JWT payload if a valid signature has
        been supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = self.decode_handler(jwt_value)
        except (jose_exceptions.JOSEError) as exc:
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
