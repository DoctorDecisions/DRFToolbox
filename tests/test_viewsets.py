# -*- coding: utf-8 -*-
import pytest
from unittest.mock import Mock

from django.db.models.deletion import ProtectedError
from rest_framework.serializers import ValidationError

from drftoolbox.viewsets import DestroyModelMixin


class TestDestroyModelMixin:

    def test_perform_destroy_raises_for_protectederror(self):
        protected = Mock()
        protected.model._meta.label = 'testmodel'
        protected.values_list.return_value = [1, 2]
        exception = ProtectedError('some db constraint', protected_objects=protected)
        exception.protected_objects = protected

        instance = Mock()
        instance.delete.side_effect=exception

        with pytest.raises(ValidationError) as exc:
            DestroyModelMixin().perform_destroy(instance)
            assert exc.message == 'Referenced by protected testmodel 1, 2'

        assert instance.delete.call_count == 1

    def test_perform_destroy_passes(self):
        instance = Mock()
        DestroyModelMixin().perform_destroy(instance)
        assert instance.delete.call_count == 1
