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


from django.http import HttpResponse, HttpResponseBadRequest

class HttpResponseUnauthorized(HttpResponse):
    status_code = 401

class OAuthError(RuntimeError):
    default_message = 'OAuth error'
    problem = 'fail'
    def __init__(self, message=None):
        self.message = message or self.__class__.default_message
        self.problem = self.__class__.problem

    def __str__(self):
        return self.problem

    def get_problem(self):
        return 'oauth_problem=%s' % self.problem

    def get_response(self):
        if isinstance(self, OAuthBadRequestError):
            return HttpResponseBadRequest(self.get_problem())
        elif isinstance(self, OAuthAuthorizationError):
            return HttpResponseUnauthorized(self.get_problem())

        return HttpResponse(self.get_problem())

class OAuthBadRequestError(OAuthError):
    pass

class OAuthAuthorizationError(OAuthError):
    pass

class OAuthUnsupportedParamError(OAuthBadRequestError):
    pass

class OAuthUnsupportedSignatureError(OAuthBadRequestError):
    default_message = 'Signature method not supported'
    problem = 'signature_method_rejected'

class OAuthMissingParamError(OAuthBadRequestError):
    default_message = 'A required parameter is missing'
    problem = 'parameter_absent'

class OAuthDuplicateParamError(OAuthBadRequestError):
    pass

class OAuthUnsupportedVersionError(OAuthBadRequestError):
    default_message = 'Unsupported protocol version'
    problem = 'version_rejected'

class OAuthInvalidConsumerError(OAuthAuthorizationError):
    default_message = 'Invalid consumer key'
    problem = 'consumer_key_unknown'

class OAuthInvalidTokenError(OAuthAuthorizationError):
    default_message = 'Invalid token'
    problem = 'token_rejected'

class OAuthInvalidSignatureError(OAuthAuthorizationError):
    default_message = 'Request signature is invalid'
    problem = 'signature_invalid'

class OAuthInvalidNonceError(OAuthAuthorizationError):
    default_message = 'This nonce has been already used'
    problem = 'nonce_used'

class OAuthInvalidTimestampError(OAuthAuthorizationError):
    default_message = 'Invalid timestamp'
    problem = 'timestamp_refused'

class OAuthInvalidSessionError(OAuthAuthorizationError):
    default_message = 'Invalid session'

class OAuthTokenExpiredError(OAuthAuthorizationError):
    default_message = 'This token has expired'
    problem = 'token_expired'

class OAuthTokenNotRenewableError(OAuthAuthorizationError):
    default_message = 'This token cannot be renewed'
    problem = 'token_not_renewable'
