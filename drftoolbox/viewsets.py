# -*- coding: utf-8 -*-
"""
    drftoolbox.viewsets
    ~~~~~~~~~~~~~~~~~~~

    This module defines viewset and classes and mixins used by the API

    :copyright: (c) 2019 by Medical Decisions LLC
"""
from django.db.models.deletion import ProtectedError
from rest_framework import mixins, serializers
from rest_framework.viewsets import GenericViewSet


class DestroyModelMixin(mixins.DestroyModelMixin):
    """
    Destroy a model instance.  Raise a validation error if a ProtectedError is raised by a database constraint.
    """

    def perform_destroy(self, instance):
        try:
            instance.delete()
        except ProtectedError as e:
            msg = 'Referenced by protected {} {}'.format(
                e.protected_objects.model._meta.label,
                ', '.join([str(x) for x in e.protected_objects.values_list('id', flat=True)])
            )
            raise serializers.ValidationError(msg)


class ModelViewSet(mixins.CreateModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.UpdateModelMixin,
                   DestroyModelMixin,
                   mixins.ListModelMixin,
                   GenericViewSet):
    """
    A viewset that provides default `create()`, `retrieve()`, `update()`, `partial_update()`, `destroy()` and `list()`
    actions.  This class incorporates system-wide customizations of the basic DRF viewet behavior; in this case, uses
    our DestroyModelMixin.
    """
    pass
