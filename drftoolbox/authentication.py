# -*- coding: utf-8 -*-
"""
    drftoolbox.authentication
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    This module defines authentication classes used by the API

    :copyright: (c) 2018 by Doctor Decisions LLC
"""
from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class Auth0JWTAuthentication(JSONWebTokenAuthentication):
    """
    Clients should authenticate by passing an Auth0 token in the "Authorization"
    HTTP header, prepended with "Bearer". For example:

        Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    auth_header_prefix = 'Bearer'

    class OverrideJWTPrefix():
        def __init__(self, prefix):
            self.prefix = prefix

        def __enter__(self):
            self.original = api_settings.JWT_AUTH_HEADER_PREFIX
            api_settings.JWT_AUTH_HEADER_PREFIX = self.prefix

        def __exit__(self, *args):
            api_settings.JWT_AUTH_HEADER_PREFIX = self.original

    def get_jwt_value(self, request):
        """
        Returns the token string for a request object, if properly formatted.
        """
        with OverrideJWTPrefix(self.auth_header_prefix):
            return super().get_jwt_value(request)

    def authenticate(self, request):
        """
        Returns a two-tuple of `Auth0User` and token if a valid signature has
        been supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        unverified_header = jwt.get_unverified_header(jwt_value)
        jwk = get_jwk(
            url='https://{}/.well-known/jwks.json'.format(settings.AUTH0['DOMAIN']),  # noqa
            kid=unverified_header.get('kid')
        )

        try:
            payload = jwt.decode(
                jwt_value,
                key=jwk,
                algorithms=unverified_header.get('alg', ['RS256']),
                issuer=settings.AUTH0['ISSUERS'],
                audience=settings.AUTH0['AUDIENCE'],
            )
        except jwt.JWTError as exc:
            raise exceptions.AuthenticationFailed(exc.args[0])

        user = Auth0User.from_payload(payload)

        return user, jwt_value
