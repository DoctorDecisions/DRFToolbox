# -*- coding: utf-8 -*-
"""
    drftoolbox.serializers
    ~~~~~~~~~~~~~~~~~~~~~~

    This module defines serializers used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
from rest_framework import serializers

from drftoolbox import authentication


class UserKMSKeySerializer(serializers.Serializer):
    encrypted_key = serializers.CharField(read_only=True)
    expiry = serializers.CharField(read_only=True)

    def _auth(self):
        assert hasattr(self.context['view'], 'http_sign_class'), (
            '{} can only be used with a view that has defined a `http_sign_class` '
            'property or function'.format(type(self).__name__)
        )
        cls = self.context['view'].http_sign_class
        return cls()() if callable(cls) else cls()

    def to_representation(self, instance):
        key, expiry = self._auth().encrypted_user_secret(instance)
        return {'encrypted_key': key, 'expiry': expiry}
