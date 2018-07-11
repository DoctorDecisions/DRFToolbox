# -*- coding: utf-8 -*-
"""
    drftoolbox.pagination
    ~~~~~~~~~~~~~~~~~~~~~

    This module provides definitions for API paginators

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import collections
import json

from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

from rest_framework import pagination, response, compat
from rest_framework.settings import api_settings



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


class ContentRangeHeaderPagination(pagination.BasePagination):
    """
    Range-based pagination which supports queries like:

    http://api.example.org/accounts/?range=[0,9]

    Adds a `Content-Range` header formatted like this, to show the current
    range (zero-based index) and the total number of items:

        Content-Range: items 0-9/50

    https://stackoverflow.com/questions/30898555/django-rest-framework-pagination-settings-content-range/30899444#30899444
    """
    range_query_param = 'range'
    range_query_description = _(
        'Zero-based start and end index within the paginated result set, in '
        'the format "[&lt;start&gt;,&lt;end&gt;]".'
    )
    page_size = api_settings.PAGE_SIZE or 100

    def paginate_queryset(self, queryset, request, view=None):
        """
        Paginate a queryset according to start/end values (zero-indexed) in
        `range` header, or `None` if pagination is not properly configured.
        """
        self.count = self.get_count(queryset)
        self.start_index = 0
        self.end_index = self.start_index + self.page_size - 1

        # TODO: this logic is repeated below...
        if self.end_index > self.count - 1:
            self.end_index = self.count - 1 if self.count else 0

        range_string = request.GET.get(self.range_query_param)

        if range_string:
            try:
                page_range = json.loads(range_string)
            except json.JSONDecodeError:
                return None

            if len(page_range) != 2:
                return None

            self.start_index, self.end_index = [pagination._positive_int(x) for x in page_range]

        if self.end_index > self.count - 1:
            self.end_index = self.count - 1 if self.count else 0

        if self.start_index > self.end_index:
            self.start_index = self.end_index

        return list(queryset[self.start_index:self.end_index + 1])

    def get_paginated_response(self, data):
        content_range = 'items {0}-{1}/{2}'.format(
            self.start_index,
            self.end_index,
            self.count
        )

        headers = {'Content-Range': content_range}

        return response.Response(data, headers=headers)

    def get_count(self, queryset):
        """
        Determine an object count, supporting either querysets or regular lists.
        """
        try:
            return queryset.count()
        except (AttributeError, TypeError):
            return len(queryset)

    def get_results(self, data):
        return data

    def get_schema_fields(self, view):
        assert compat.coreapi is not None, 'coreapi must be installed to use `get_schema_fields()`'
        assert compat.coreschema is not None, 'coreschema must be installed to use `get_schema_fields()`'
        fields = [
            compat.coreapi.Field(
                name=self.range_query_param,
                required=False,
                location='query',
                schema=compat.coreschema.Array(
                    title='Range',
                    description=force_text(self.range_query_description),
                    items=compat.coreschema.Integer(),
                    min_items=2,
                    max_items=2,
                )
            )
        ]
        return fields
