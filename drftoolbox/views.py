# -*- coding: utf-8 -*-
"""
    drftoolbox.views
    ~~~~~~~~~~~~~~~~

    This module defines view classes used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import datetime
import logging

from django.contrib.auth import get_user_model
from rest_framework import generics

from drftoolbox.authentication import BaseKMSSecretAPISignatureAuthentication
from drftoolbox.serializers import UserKMSKeySerializer

LOGGER = logging.getLogger(__name__)

class BaseUserKMSKeyView(generics.RetrieveAPIView):
    queryset = get_user_model().objects.filter(is_active=True)
    serializer_class = UserKMSKeySerializer

    def http_sign_class(self):
        raise NotImplementedError
