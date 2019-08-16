# -*- coding: utf-8 -*-
from unittest.mock import MagicMock

from django.http import Http404
from django.core.exceptions import PermissionDenied
from django.test import TestCase

from djangorestframework_camel_case.render import CamelCaseJSONRenderer
from rest_framework import views, serializers

from drftoolbox import handlers


class ChildSerializer(serializers.Serializer):
    __test__ = False
    name = serializers.CharField()

    def validate_name(self, val):
        if val == 'invalid':
            raise serializers.ValidationError('bad name')
        return val


class TestSerializer(serializers.Serializer):
    __test__ = False
    name = serializers.CharField()
    value = serializers.CharField()
    detail = serializers.CharField(required=False)
    underscore_field = serializers.CharField(required=False)
    child = ChildSerializer(required=False)
    children = ChildSerializer(many=True, required=False)
    array = serializers.ListField(child=serializers.CharField(), required=False)

    def validate(self, data):
        if data.get('name') == 'invalid' or data.get('value') == 'invalid':
            raise serializers.ValidationError('one bad value')

    def validate_detail(self, value):
        if value == 'none':
            raise serializers.ValidationError('cant use none')
        return value

    def validate_underscore_field(self, value):
        if value == 'none':
            raise serializers.ValidationError('cant use none')
        return value


class ExceptionHandlerTests(TestCase):
    def test_not_found(self):
        exc = Http404()
        resp = handlers.error_list_exception_handler(exc, {})
        assert resp.status_code == 404
        assert resp.data == {
                'errors': [
                    {
                        'code': 'not_found',
                        'message': 'Not found.',
                    },
                ]
            }

    def test_permission_denied(self):
        exc = PermissionDenied()
        resp = handlers.error_list_exception_handler(exc, {})
        assert resp.status_code == 403
        assert resp.data == {
                'errors': [
                    {
                        'code': 'permission_denied',
                        'message': 'You do not have permission to perform this action.',
                    },
                ]
            }

    def test_non_field_error(self):
        data = {'name': 'invalid', 'value': 'invalid'}
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            resp = handlers.error_list_exception_handler(exc, {})
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'invalid',
                            'message': 'one bad value',
                            'source': '',
                        },
                    ]
                }

    def test_field_error(self):
        data = {'name': 'valid'}
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            resp = handlers.error_list_exception_handler(exc, {})
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'required',
                            'message': 'This field is required.',
                            'source': '/value',
                        },
                    ]
                }

    def test_nested_serializer_field(self):
        data = {
            'name': 'test',
            'value': 'valid',
            'child': {'name': 'invalid'},
        }
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            resp = handlers.error_list_exception_handler(exc, {})
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'invalid',
                            'message': 'bad name',
                            'source': '/child/name',
                        },
                    ]
                }

    def test_nested_many_serializer_field(self):
        data = {
            'name': 'test',
            'value': 'valid',
            'children': [{'name': 'ok'}, {'name': 'invalid'}],
        }
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            resp = handlers.error_list_exception_handler(exc, {})
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'invalid',
                            'message': 'bad name',
                            'source': '/children/1/name',
                        },
                    ]
                }

    def test_multiple_field_errors(self):
        data = {}
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            resp = handlers.error_list_exception_handler(exc, {})
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'required',
                            'message': 'This field is required.',
                            'source': '/name',
                        },
                        {
                            'code': 'required',
                            'message': 'This field is required.',
                            'source': '/value',
                        },
                    ]
                }

    def test_validation_error(self):
        exc = serializers.ValidationError('value error')
        resp = handlers.error_list_exception_handler(exc, {})
        assert resp.status_code == 400
        assert resp.data == {
                'errors': [
                    {
                        'code': 'invalid',
                        'message': 'value error',
                    },
                ]
            }
        exc = serializers.ValidationError('value error', code='wrong_value')
        resp = handlers.error_list_exception_handler(exc, {})
        assert resp.status_code == 400
        assert resp.data == {
                'errors': [
                    {
                        'code': 'wrong_value',
                        'message': 'value error',
                    },
                ]
            }

    def test_validation_error_detail_field(self):
        data = {'name': 'valid', 'value': 'valid', 'detail': 'none'}
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            resp = handlers.error_list_exception_handler(exc, {})
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'invalid',
                            'message': 'cant use none',
                            'source': '/detail',
                        },
                    ]
                }

    def test_validation_error_detail_field_camelcase_renderer(self):
        data = {'name': 'valid', 'value': 'valid', 'underscore_field': 'none'}
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            context = {'view': views.APIView(), 'request': None}
            context['view'].perform_content_negotiation = \
                MagicMock(return_value=(CamelCaseJSONRenderer(), 'application/json'))
            resp = handlers.error_list_exception_handler(exc, context)
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'invalid',
                            'message': 'cant use none',
                            'source': '/underscoreField',
                        },
                    ]
                }

    def test_validation_error_with_array(self):
        data = {'name': 'valid', 'value': 'valid', 'array': [None]}
        serializer = TestSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as exc:
            resp = handlers.error_list_exception_handler(exc, {})
            assert resp.status_code == 400
            assert resp.data == {
                    'errors': [
                        {
                            'code': 'null',
                            'message': 'This field may not be null.',
                            'source': '/array/0',
                        },
                    ]
                }
