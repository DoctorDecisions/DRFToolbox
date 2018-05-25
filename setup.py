#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import os

from setuptools import setup

REQUIRES_PYTHON = '>=3.6.0'
# What packages are required for this module to be executed?
REQUIRED = [
    'djangorestframework>=3.0.0',
    'Django>=1.11.0',
    'flatdict',
]
TESTS_REQUIRED = [
    'pytest>=4.0.0',
    'pytest-cov>=2.5.0',
    'pytest-django>=3.1.2'
]

here = os.path.abspath(os.path.dirname(__file__))

# Import the README and use it as the long-description.
# Note: this will only work if 'README.md' is present in your MANIFEST.in file!

# Load the package's __version__.py module as a dictionary.
about = {}
with open(os.path.join(here, 'drftoolbox', '__version__.py'), 'r', 'utf-8') as f:
    exec(f.read(), about)
with open('README.md', 'r', 'utf-8') as f:
    readme = f.read()


# Where the magic happens:
setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__description__'],
    long_description=readme,
    long_description_content_type='text/markdown',
    author=about['__author__'],
    author_email=about['__author_email__'],
    python_requires=REQUIRES_PYTHON,
    url=about['__url__'],
    py_modules=['drftoolbox'],
    install_requires=REQUIRED,
    tests_require=TESTS_REQUIRED,
    include_package_data=True,
    license='MIT',
    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.10',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy'
    ],
)
