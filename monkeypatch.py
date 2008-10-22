# -*- coding: utf-8 -*-

# Copyright (c) 2008 Alberto García Hierro <fiam@rm-fr.net>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from django.http import HttpRequest

from oauthsp.request import OAuthRequest

# This code is only for your convenience in case
# you want to use it. Nor django-oauthsp nor
# WAPI require it.
# Just do from oauthsp.monkeypatch import *
# and all the HttpRequest objects will have
# a get_oauth() method which returns the OAuth
# request associated with it or None if the
# HttpRequest does not contain OAuth information.

def get_oauth_request(self):
    if not hasattr(self, '_oauth'):
        self._oauth = OAuthRequest(self)
        if not self._oauth.is_oauth():
            self._oauth = None
        else:
            self._oauth.validate_access()
            self.user = self._oauth.token.user

    return self._oauth

HttpRequest.get_oauth = get_oauth_request
