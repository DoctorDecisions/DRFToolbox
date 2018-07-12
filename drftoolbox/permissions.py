# -*- coding: utf-8 -*-
"""
    drftoolbox.permissions
    ~~~~~~~~~~~~~~~~~~~~~~

    This module defines permission classes used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
from rest_framework import permissions


class StrictDjangoModelPermissions(permissions.DjangoModelPermissions):
    """
    DjangoModelPermissions implementation which requires a `view_*` model
    permission for `GET`.  That permission is not created by Django by default
    until version 2.1, and unhandled by DRF as of version 3.8.
    """
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }
