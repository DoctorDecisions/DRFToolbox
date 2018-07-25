# -*- coding: utf-8 -*-
import json

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.urls import path
from rest_framework import viewsets, response
from rest_framework.reverse import reverse

from drftoolbox import utils


class InlineRendererViewSet(viewsets.ViewSet):
    def test(self, request):
        if 'q' in request.query_params:
            return response.Response({'data': 'test with q'})
        return response.Response({'data': 'test'})

urlpatterns = [
    path('test/', InlineRendererViewSet.as_view({'get': 'test'})),
]


class InlineRenderTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.request = self.factory.get('/')
        self.request.urlconf = __name__

    def test_get_for_view(self):
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        resp = utils.inline_render('GET', '/test/', self.request)
        assert resp == {'data': 'test'}

    def test_get_for_view_with_querydict(self):
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        resp = utils.inline_render('GET', '/test/', self.request,
            query_dict={'q': True})
        assert resp == {'data': 'test with q'}

    def test_get_for_view_with_accepts(self):
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        resp = utils.inline_render('GET', '/test/', self.request,
            accepts='application/json')
        assert resp == '{"data":"test"}'
