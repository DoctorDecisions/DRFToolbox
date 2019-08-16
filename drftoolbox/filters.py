# -*- coding: utf-8 -*-
"""
    drftoolbox.filters
    ~~~~~~~~~~~~~~~~~~

    This module defines filters used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import collections

from django.utils.encoding import force_text
from rest_framework import metadata


class FilterMetadata(metadata.SimpleMetadata):
    """
    Similar to the default SimpleMetadata class, but this one will provide
    information on the Filters if the View defines them.
    """
    def determine_metadata(self, request, view):
        md = super().determine_metadata(request, view)
        if hasattr(view, 'filterset_class'):
            filters = collections.OrderedDict()
            for name, _filter in view.filterset_class.base_filters.items():
                name = name.split('__')[0]
                attrs = collections.OrderedDict()
                attrs['type'] = _filter.__class__.__name__
                choices = _filter.extra.get('choices', False)
                if choices:
                    attrs['choices'] = []
                    for cvalue, cname in choices:
                        attrs['choices'].append({
                            'value': cvalue,
                            'display_name': force_text(cname, strings_only=True),
                        })
                filters[name] = attrs
            md['filters'] = filters
        return md
