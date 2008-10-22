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

import time
from datetime import datetime

from django.http import HttpRequest

from oauthsp import exceptions
from oauthsp.signatures import get_signature_method
from oauthsp.utils import quote, unquote
from oauthsp.models import Consumer, Token, Nonce

OAUTH_PREFIX = 'oauth_'
VERSION = '1.0'

class OAuthRequest(object):
    def __init__(self, request):
        self.request = request
        self.consumer = None
        self.token = None

    def base_uri(self):
        return '%s://%s%s' % (self.request.is_secure() and 'https' or 'http',
                self.request.get_host().lower(), self.request.path)

    def normalized_params(self):
        key_values = []
        if self.has_oauth_header():
            for k, v in self.OAUTH.items():
                if k != 'signature':
                    key_values.append((OAUTH_PREFIX + k, v))

        if self.request.POST and \
            self.request.META['CONTENT_TYPE'] == 'application/x-www-form-urlencoded':

            dcts = (self.request.POST, self.request.GET)
        else:
            dcts = (self.request.GET, )
        for dct in dcts:
            for k in dct:
                if k != OAUTH_PREFIX + 'signature':
                    for value in dct.getlist(k):
                        key_values.append((k, value))
        key_values.sort()

        return u'&'.join(u'%s=%s' % (quote(unicode(k)), quote(unicode(v))) for k, v in key_values)

    def signature_base_string(self):
        return u'%s&%s&%s' % (self.request.method, quote(self.base_uri()), quote(self.normalized_params()))

    def has_oauth_header(self):
        return 'HTTP_AUTHORIZATION' in self.request.META and \
            self.request.META['HTTP_AUTHORIZATION'].find('OAuth') > -1

    def has_oauth_get(self):
        return 'oauth_consumer_key' in self.request.GET

    def has_oauth_post(self):
        return 'oauth_consumer_key' in self.request.POST

    def is_oauth(self):
        return self.has_oauth_header() or self.has_oauth_get() or self.has_oauth_post()

    def oauth_from_header(self):
        oauth = {}
        for param in [p.strip() for p in self.request.META['HTTP_AUTHORIZATION'].split(',')]:
            if param.find('OAuth realm') > -1:
                continue
            try:
                k, v = param.split('=', 1)
            except ValueError:
                continue
            if k.startswith(OAUTH_PREFIX):
                oauth[k[len(OAUTH_PREFIX):]] = unquote(v.strip('"'))

        return oauth

    def oauth_from_dict(self, dct):
        oauth = {}
        for k, v in dct.items():
            if k.startswith(OAUTH_PREFIX):
                oauth[k[len(OAUTH_PREFIX):]] = unquote(v)

        return oauth

    @property
    def OAUTH(self):
        if not hasattr(self, '_oauth'):
            if self.has_oauth_header():
                self._oauth = self.oauth_from_header()
            elif self.has_oauth_get():
                self._oauth = self.oauth_from_dict(self.request.GET)
            elif self.has_oauth_post():
                self._oauth = self.oauth_from_dict(self.request.POST)
            else:
                self._oauth = {}

        return self._oauth

    def validate_consumer(self):
        try:
            self.consumer = Consumer.objects.get(key=self.OAUTH['consumer_key'])
        except (KeyError, Consumer.DoesNotExist):
            raise exceptions.OAuthInvalidConsumerError

    def validate_token(self):
        if self.OAUTH.get('token'):
            try:
                self.token = Token.objects.get(consumer=self.consumer, key=self.OAUTH['token'])
            except Token.DoesNotExist:
                raise exceptions.OAuthInvalidTokenError

    def validate_timestamp(self):
        try:
            val = int(self.OAUTH['timestamp'])
        except (KeyError, ValueError, TypeError):
            raise exceptions.OAuthInvalidTimestampError

        if not -150 < time.time() - val < 150:
            raise exceptions.OAuthInvalidTimestampError

    def validate_version(self):
        version = self.OAUTH.get('version')
        if version and version != VERSION:
            raise exceptions.OAuthUnsupportedVersionError('Version "%s" is not supported' % version)

    def validate_nonce(self):
        try:
            nonce, cr = Nonce.objects.get_or_create(consumer=self.consumer,
                    token=self.token, value=self.OAUTH['nonce'])
        except KeyError:
            raise exceptions.OAuthInvalidNonceError

        if not cr:
            raise exceptions.OAuthInvalidNonceError

    def validate_signature(self):
        signature_method = get_signature_method(self.OAUTH.get('signature_method'))
        if not signature_method.validate(self):
            raise exceptions.OAuthInvalidSignatureError

    def validate(self):
        self.validate_version()
        self.validate_timestamp()
        self.validate_consumer()
        self.validate_token()
        self.validate_nonce()
        self.validate_signature()

    def validate_access(self):
        self.validate()
        if not self.token or not self.token.is_access():
            raise exceptions.OAuthInvalidTokenError
        if self.token.expiration_date < datetime.now():
            raise exceptions.OAuthTokenExpiredError

    def validate_session(self):
        try:
            if self.token and self.token.session_handle != self.OAUTH['session_handle']:
                raise exceptions.OAuthInvalidTokenError
        except KeyError:
            raise exceptions.OAuthMissingParamError

    def generate_request_token(self):
        self.validate()
        token = Token(consumer=self.consumer)
        try:
            duration = int(self.OAUTH.get('token_duration'))
            token.duration = duration
        except (TypeError, ValueError):
            pass

        token.save()
        token.attrs.set_attributes(self.OAUTH.get('token_attributes'))
        return token

