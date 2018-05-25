#: utf-8 -*-
import copy

from django.test import TestCase
from django.conf import settings

from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from drftoolbox import pagination



class ContentRangeHeaderPaginationTests(TestCase):
    def setUp(self):
        self.paginator = pagination.ContentRangeHeaderPagination()

    @staticmethod
    def request(method, *args, **kwargs):
        request = getattr(APIRequestFactory(), method)(*args, **kwargs)
        return APIView().initialize_request(request)

    def test_no_data(self):
        data = []
        request = self.request('get', '/')
        self.paginator.page_size = 30
        self.paginator.paginate_queryset(data, request)
        resp = self.paginator.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-0/0'

    def test_data(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/')
        self.paginator.page_size = 30
        self.paginator.paginate_queryset(data, request)
        resp = self.paginator.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-2/3'

    def test_first_page(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/', {'page': 1,})
        self.paginator.page_size = 1
        self.paginator.paginate_queryset(data, request)
        resp = self.paginator.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-0/3'

    def test_middle_page(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}]
        request = self.request('get', '/', {'page': 2,})
        self.paginator.page_size = 2
        self.paginator.paginate_queryset(data, request)
        resp = self.paginator.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 2-3/5'

    def test_last_page(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/', {'page': 'last',})
        self.paginator.page_size = 1
        self.paginator.paginate_queryset(data, request)
        resp = self.paginator.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 2-2/3'

