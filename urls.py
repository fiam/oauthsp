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

from django.conf.urls.defaults import patterns, url

urlpatterns = patterns('oauthsp.views',
    url(r'^consumer/(?P<consumer_id>\d+)/$', 'consumer', name='consumer'),
    url(r'^consumer/(?P<consumer_id>\d+)/edit/$', 'edit_consumer', name='edit-consumer'),
    url('^new-consumer/$', 'new_consumer', name='new-consumer'),
    url('^consumers/((?P<page>\d+)/)?$', 'consumers', name='consumers'),
    url('^revoke/$', 'revoke', name='revoke'),
    url('^revoke/(?P<token_id>\d+)/$', 'revoke', name='revoke-token'),
    url('^request_token$', 'request_token', name='request-token'),
    url('^access_token$', 'access_token', name='access-token'),
    url('^authorize$', 'authorize', name='authorize-token'),
)
