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

import hmac
import hashlib
from base64 import b64encode

from oauthsp.utils import quote
from oauthsp import exceptions

__all__ = [
    'get_signature_method'
    'OAuthSignature',
    'OAuthSignature_HMAC_SHA1',
    'OAuthSignature_PLAINTEXT',
]

OAUTH_SIGNATURE_METHODS = {}

def get_signature_method(sm):
    try:
        return OAUTH_SIGNATURE_METHODS[sm]
    except KeyError:
        raise exceptions.OAuthUnsupportedSignatureError('"%s" is not a valid signature method' % sm)

class OAuthSignatureType(type):
    def __init__(cls, name, bases, dct):
        super(OAuthSignatureType, cls).__init__(name, bases, dct)
        instance = cls()
        try:
            OAUTH_SIGNATURE_METHODS[instance.get_name()] = instance
        except NotImplementedError:
            pass

class OAuthSignature(object):
    __metaclass__ = OAuthSignatureType

    def get_name(self):
        raise NotImplementedError

    def get_key(self, request):
        if request.token:
            return '%s&%s' % \
                (quote(request.consumer.secret),
                quote(request.token.secret))

        return '%s&' % quote(request.consumer.secret)

    def get_base_string(self, request):
        raise NotImplementedError

    def sign_string(self, key, s):
        raise NotImplementedError

    def signature(self, request):
        return b64encode(self.sign_string(self.get_key(request),
            self.get_base_string(request)))

    def validate(self, request):
        try:
            return self.signature(request) == request.OAUTH['signature']
        except KeyError:
            return False


class OAuthSignature_HMAC_SHA1(OAuthSignature):
    def get_name(self):
        return 'HMAC-SHA1'

    def get_base_string(self, request):
        return request.signature_base_string()

    def sign_string(self, key, s):
        hashed = hmac.new(key, s, hashlib.sha1)
        return hashed.digest()


class OAuthSignature_PLAINTEXT(OAuthSignature):
    def get_name(self):
        return 'PLAINTEXT'

    def get_base_string(self, request):
        return ''

    def sign_string(self, key, s):
        return key

