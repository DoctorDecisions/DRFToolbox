# -*- coding: utf-8 -*-
import json

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.urls import path
from rest_framework import views, viewsets, response, request
from rest_framework.reverse import reverse

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


class InlineRenderTests(TestCase):
    def setUp(self):
        self.request = RequestFactory().get('/')
        self.request.urlconf = __name__

    def test_get_for_viewset(self):
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        resp = utils.inline_render('GET', '/test-vs/', self.request)
        assert resp == {'data': 'test-vs'}

    def test_get_for_viewset_with_drf_request(self):
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        req = request.Request(self.request)
        resp = utils.inline_render('GET', '/test-vs/', req)
        assert resp == {'data': 'test-vs'}

    def test_get_for_viewset_with_querydict(self):
        self.request.GET
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        resp = utils.inline_render('GET', '/test-vs/', self.request,
            query_dict={'q': True})
        assert resp == {'data': 'test-vs with q'}

    def test_get_for_viewset_with_accepts(self):
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        resp = utils.inline_render('GET', '/test-vs/', self.request,
            accepts='application/json')
        assert resp == '{"data":"test-vs"}'

    def test_get_for_view(self):
        self.request.user = get_user_model().objects.create_user('test', 'pass')
        resp = utils.inline_render('GET', '/test-v/', self.request)
        assert resp == {'data': 'test-v'}
