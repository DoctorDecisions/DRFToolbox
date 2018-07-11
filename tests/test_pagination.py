#: utf-8 -*-
"""
    drftoolbox.tests.test_pagination
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This module provides test cases for pagination modules

    :copyright: (c) 2018 by Medical Decisions LLC
"""
from django.test import TestCase
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from drftoolbox import pagination


class ContentRangeHeaderPaginationTests(TestCase):

    @staticmethod
    def request(method, *args, **kwargs):
        request = getattr(APIRequestFactory(), method)(*args, **kwargs)
        return APIView().initialize_request(request)

    def test_no_data(self):
        data = []
        request = self.request('get', '/')
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 0
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-0/0'

    def test_data(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/')
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 3
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-2/3'

    def test_first_range(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/', {'range': '[0,0]'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 1
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-0/3'

    def test_middle_range(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}]
        request = self.request('get', '/', {'range': '[2,3]'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 2
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 2-3/5'

    def test_last_range(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/', {'range': '[2,2]'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 1
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 2-2/3'

    def test_range_end_too_high(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/', {'range': '[0,10]'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 3
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-2/3'

    def test_range_start_too_high(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/', {'range': '[2,1]'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 1
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 1-1/3'

    def test_invalid_range_format(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}, {'id': 4}, {'id': 5}]
        request = self.request('get', '/', {'range': '[2,3'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert qs is None
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-4/5'

        request = self.request('get', '/', {'range': '2,3'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert qs is None
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-4/5'

        request = self.request('get', '/', {'range': '[2,3,4]'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert qs is None
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-4/5'

        request = self.request('get', '/', {'range': '["foo"]'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert qs is None
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-4/5'

        request = self.request('get', '/', {'range': '['})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert qs is None
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-4/5'

        request = self.request('get', '/', {'range': 'invalid'})
        p = pagination.ContentRangeHeaderPagination()
        qs = p.paginate_queryset(data, request)
        assert qs is None
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-4/5'

    def test_default_page_size(self):
        data = [{'id': 1}, {'id': 2}, {'id': 3}]
        request = self.request('get', '/')
        p = pagination.ContentRangeHeaderPagination()
        p.page_size = 2
        qs = p.paginate_queryset(data, request)
        assert len(qs) == 2
        resp = p.get_paginated_response(data)
        assert 'Content-Range' in resp
        assert resp['Content-Range'] == 'items 0-1/3'
