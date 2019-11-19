# -*- coding: utf-8 -*-
from unittest import mock

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from django.urls import path
from rest_framework import views, viewsets, response, request
import pytest

from drftoolbox import utils


class InlineRendererViewSet(viewsets.ViewSet):
    def test(self, request):
        if 'q' in request.query_params:
            return response.Response({'data': 'test-vs with q'})
        return response.Response({'data': 'test-vs'})


class InlineRendererView(views.APIView):
    def get(self, request):
        return response.Response({'data': 'test-v'})

urlpatterns = [
    path('test-vs/', InlineRendererViewSet.as_view({'get': 'test'})),
    path('test-v/', InlineRendererView.as_view()),
]


@override_settings(ROOT_URLCONF=__name__)
class InlineRenderTests(TestCase):
    def setUp(self):
        self.request = RequestFactory().get('/')
        self.request.user = get_user_model().objects.create_user('test', 'pass')

    def test_get_no_render(self):
        resp = utils.inline_render('GET', '/missing/', self.request)
        assert resp.status_code == 404

    def test_get_for_viewset(self):
        resp = utils.inline_render('GET', '/test-vs/', self.request)
        assert resp.data == {'data': 'test-vs'}

    def test_get_for_viewset_with_drf_request(self):
        req = request.Request(self.request)
        resp = utils.inline_render('GET', '/test-vs/', req)
        assert resp.data == {'data': 'test-vs'}

    def test_get_for_viewset_with_querydict(self):
        self.request.GET
        resp = utils.inline_render('GET', '/test-vs/', self.request,
            query_dict={'q': True})
        assert resp.data == {'data': 'test-vs with q'}

    def test_get_for_viewset_with_accepts(self):
        resp = utils.inline_render('GET', '/test-vs/', self.request,
            accepts='application/json')
        assert resp.data == '{"data":"test-vs"}'

    def test_get_for_view(self):
        resp = utils.inline_render('GET', '/test-v/', self.request)
        assert resp.data == {'data': 'test-v'}


class TestValidFuncArgs(TestCase):
    def echo(self, val):
        return val

    def test_valid_func_args(self):
        assert utils.valid_func_args(self.echo, 'val') is True

    def test_invalid_func_args(self):
        pytest.deprecated_call(utils.valid_func_args, self.echo, 'value')

    def test_mock_func(self):
        func = mock.MagicMock(return_value=1)
        pytest.deprecated_call(utils.valid_func_args, func, 'value')
