# -*- coding: utf-8 -*-
"""
    drftoolbox.utils
    ~~~~~~~~~~~~~~~~

    This module defines handlers used by the API

    :copyright: (c) 2018 by Medical Decisions LLC
"""
import copy
import inspect
import warnings

from django.http import Http404, HttpResponseNotFound
from django.urls import resolve
from django.utils.http import urlencode


def inline_render(method, url, request, query_dict=None, accepts=None):
    """
    This method provides a shortcut for directly rendering an API view.  You
    could also make the request inline using something like `urllib.request` or
    `requests`, but both of those methods will have additionally overhead as
    another connection will need to be made, and it will only work if the
    application server is not single threaded.  This method bypasses that by
    calling the API view.  This could be useful for say bootstrapping an
    initial API call with other data elements.
    """
    # the viewsets module references the API settings, thus if you try to
    # use these utility functions early on (say when you are defining the API
    # settings) a circular dep error will occur.
    from rest_framework import viewsets
    try:
        resolver = resolve(url)
        if hasattr(request, '_request'):
            request = request._request
        request = copy.copy(request)
        request.path = url
        request.method = method
        if query_dict:
            qd = urlencode(query_dict)
            qs = request.META['QUERY_STRING']
            request.META['QUERY_STRING'] = '{}&{}'.format(qs, qd) if qs else qd
            # An immutable QueryDict is cached on `GET`, so explicitly delete
            # the cached value so next access rebuilds it with the above changes.
            # This covers direct Django requests and DRF requests that wrap the
            # original request into `_request`.
            if 'GET' in request.__dict__.keys():
                del request.GET
        # Directly call the corresponding action from the `as_view()` configuration
        # based on the given method and current request.
        func = resolver.func
        if isinstance(func.cls(), viewsets.ViewSetMixin):
            view_kwargs = func.initkwargs
            view_kwargs['actions'] = getattr(func, 'actions', None)
        else:
            view_kwargs = func.view_initkwargs
        view = resolver.func.cls.as_view(**view_kwargs)
        if accepts is not None:
            request.META['HTTP_ACCEPT'] = accepts
        resp = view(request, *resolver.args, **resolver.kwargs)
        if accepts:
            resp.renderer_context['response'] = resp
            resp.data = resp.accepted_renderer.render(resp.data,
                renderer_context=resp.renderer_context).decode()
        return resp
    except Http404:
        return HttpResponseNotFound()


def valid_func_args(func, *args):
    """
    Helper function to test that a function's parameters match the desired
    signature, if not then issue a deprecation warning.
    """
    keys = inspect.signature(func).parameters.keys()
    if set(args) == set(keys):
        return True
    label = getattr(func, '__name__', str(func))
    msg = (
        f'{label}({", ".join(keys)}) is deprecated, please override '
        f'with {label}({", ".join(args)})'
    )
    warnings.warn(msg, DeprecationWarning)
    return False
