# -*- coding: utf-8 -*-
"""
    drftoolbox.pagination
    ~~~~~~~~~~~~~~~~~~~~~

    This module provides definitions for API paginators

    :copyright: (c) 2018 by Doctor Decisions LLC
"""
import collections

from rest_framework import pagination, response


class PageNumberPagination(pagination.PageNumberPagination):
    """ 
    Allow client to set page size for pagination
    """
    page_size_query_param = 'page_size'

    def get_paginated_response(self, data):
        return response.Response(collections.OrderedDict([
            ('count', self.page.paginator.count),
            ('page', self.page.number),
            ('num_pages', self.page.paginator.num_pages),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('results', data)
        ]))


class ContentRangeHeaderPagination(pagination.PageNumberPagination):
    """
    Adds a `Content-Range` header formatted like this:

    Content-Range: items 0-9/50

    https://stackoverflow.com/questions/30898555/django-rest-framework-pagination-settings-content-range/30899444#30899444
    """
    def get_paginated_response(self, data):
        total_items = self.page.paginator.count

        # In a page, indexing starts from 1
        item_starting_index = self.page.start_index() - 1 if total_items else 0
        item_ending_index = self.page.end_index() - 1 if total_items else 0

        content_range = 'items {0}-{1}/{2}'.format(
            item_starting_index,
            item_ending_index,
            total_items
        )

        headers = {'Content-Range': content_range}

        return response.Response(data, headers=headers)
