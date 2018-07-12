# -*- coding: utf-8 -*-
"""
    drftoolbox.handlers
    ~~~~~~~~~~~~~~~~~~~

    This module defines handlers used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import warnings

from django.http import Http404
from django.core.exceptions import PermissionDenied

import flatdict
from rest_framework import exceptions, views, settings


def error_list_exception_handler(exc, context, delimiter='/'):
    """
    Enhanced version of the default DRF exception handler that consolidates all
    of the error detail dicts into a list, and nests that list under a top
    level 'errors' key.  For example:

    ```
    {
        'errors': [
            {
                'code': 'required',
                'message': 'This field is required.',
                'source': '/name'
            },
            {
                'code': 'required',
                'message': 'This field is required.',
                'source': '/value'
            },
        ]
    }
    ```
    """
    def update_key_for_renderer(key, view, request):
        renderer, media_type = view.perform_content_negotiation(request, force=True)
        if type(renderer).__name__ == 'CamelCaseJSONRenderer':
            try:
                from djangorestframework_camel_case.util import camelize
                return list(camelize({key: None}).keys())[0]
            except ImportError:
                warnings.warn('djangorestframework-camel-case is not installed, '
                    'source keys may not render properly')
        return key

    # convert Django 404s and 403s into the DRF equivalents, this is needed so
    # we can get the full details of the exception
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()

    # process the exception by the default exception handler to get the response
    # that we need to edit, if that handler can't process it, then return None
    resp = views.exception_handler(exc, context)
    if resp is None:
        return

    details = exc.get_full_details()

    if not isinstance(exc, exceptions.ValidationError) or isinstance(details, list):
        # case 1)
        # exception is a validation error or the validation error is top level
        if not isinstance(details, list):
            details = [details]
        resp.data = {'errors': details}
        return resp

    # case 2) the validation errors are nested underneath field
    # name keys
    flattened = flatdict.FlatterDict(details, delimiter)
    fields = {}
    # the error data can be nested into an arbitrary number of levels because of
    # nested serializers, so first build up a dict of all source fields
    for key, value in flattened.items():
        # use rsplit to build from the back, so the last 2 items are guaranteed
        # to be the list index and the error key (code, message, etc).  That
        # leaves the entire first item of the tuple as a pointer to the source
        # field
        field, idx, attr = key.rsplit(delimiter, 2)
        if field not in fields:
            fields[field] = {}
        if idx not in fields[field]:
            fields[field][idx] = {}
        fields[field][idx].update({attr: value})

    errors = []
    for field, data in sorted(fields.items()):
        # with the dict of source fields to data errors, ungroup the index keys
        # and add the error to the list
        if field == settings.api_settings.NON_FIELD_ERRORS_KEY:
            # TODO: should resetting the field be parameterized
            field = ''
        if 'view' in context and 'request' in context:
            field = update_key_for_renderer(field, context['view'], context['request'])
        for idx, err in data.items():
            if field:
                field = '{}{}'.format(delimiter, field)
            err['source'] = field
            errors.append(err)
    resp.data = {'errors': errors}
    return resp
