#!/usr/bin/env python
"""
Added functionality for a CEDA-themed PyDAP distribution

"""
__author__ = "William Tucker"
__copyright__ = "Copyright (c) 2014, Science & Technology Facilities Council (STFC)"
__license__ = "BSD - see LICENSE file in top-level directory"

from distutils.core import setup
from setuptools import find_packages
import re
import os

v_file = open(os.path.join(os.path.dirname(__file__), 
                       'dj_ssl_authn_middleware', '__init__.py'))

THIS_DIR = os.path.dirname(__file__)

SHORT_DESCR = ''
try:
    LONG_DESCR = open(os.path.join(THIS_DIR, 'README.md')).read()
except IOError:
    LONG_DESCR = SHORT_DESCR

setup(
    name='dj-ssl-authn-middleware',
    version = '1.0.1',
    author=u'William Tucker',
    author_email='william.tucker@stfc.ac.uk',
    package_dir = {'dj_ssl_authn_middleware':'dj_ssl_authn_middleware'},
    packages=find_packages(),
    url='',
    license='BSD licence, see LICENCE',
    description=SHORT_DESCR,
    long_description=LONG_DESCR,
    zip_safe=False,

    # Adds dependencies    
    install_requires = ['Django',
                        'pyopenssl',
                        'crypto_cookie'],
)
