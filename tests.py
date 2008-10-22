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

import unittest

from django.http import QueryDict

from oauthsp.models import Consumer, Token
from oauthsp.request import OAuthRequest
from oauthsp.signatures import OAuthSignature_HMAC_SHA1
from oauthsp.utils import quote, unquote

class MockRequest(object):
    def __init__(self, *attrs, **kw):
        self.host, self.path = '', ''
        self.secure = False
        self.GET, self.POST, self.REQUEST, self.META = {}, {}, {}, {}
        for attr in attrs:
            setattr(self, attr[0], QueryDict(attr[1]))

        for k, v in kw.items():
            setattr(self, k, v)

        if kw.get('uri'):
            uri = kw['uri']
            self.secure = uri.startswith('https')
            self.host = uri.split('/')[2]
            self.path = '/'.join(uri.split('/')[3:])
            if self.path:
                self.path = '/%s' % self.path

    def get_host(self):
        return self.host

    def is_secure(self):
        return self.secure

class OAuthRequestTestCase(unittest.TestCase):
    def testEncoding(self):
        params = (
            (u'abcABC123', u'abcABC123'),
            (u'-._~', u'-._~'),
            (u'%', u'%25'),
            (u'+', u'%2B'),
            (u'&=*', u'%26%3D%2A'),
            (unichr(0x000A), u'%0A'),
            (unichr(0x0020), u'%20'),
            (unichr(0x007F), u'%7F'),
            (unichr(0x0080), u'%C2%80'),
            (unichr(0x3001), u'%E3%80%81'),
        )
        for p in params:
            self.assertEqual(quote(p[0]), p[1])
            self.assertEqual(unquote(quote(p[0])), p[1])

    def testNormalization(self):
        query_strings = (
            ('name', 'name='),
            ('a=b', 'a=b'),
            ('a=b&c=d', 'a=b&c=d'),
            ('a=x!y&a=x+y', 'a=x%20y&a=x%21y'),
            ('x!y=a&x=a', 'x=a&x%21y=a'),
        )
        for qs in query_strings:
            req = OAuthRequest(MockRequest(('GET', qs[0])))
            self.assertEqual(req.normalized_params(), qs[1])

    def testConcatenate(self):
        requests = (
            (
                'GET',
                'http://example.com',
                'n=v',
                'GET&http%3A%2F%2Fexample.com&n%3Dv'
            ),
            (
                'POST',
                'https://photos.example.net/request_token',
                    'oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&' \
                    'oauth_timestamp=1191242090&oauth_nonce=hsu94j3884jdopsl&' \
                    'oauth_signature_method=PLAINTEXT&oauth_signature=ignored',
                'POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&oauth' \
                    '_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j' \
                    '3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth' \
                    '_timestamp%3D1191242090%26oauth_version%3D1.0'
            ),
            (
                'GET',
                'http://photos.example.net/photos',
                    'file=vacation.jpg&size=original&oauth_version=1.0&' \
                    'oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch' \
                    '734d00sl2jdk&oauth_timestamp=1191242096&oauth_nonce=' \
                    'kllo9940pd9333jh&oauth_signature=ignored&oauth_signa' \
                    'ture_method=HMAC-SHA1',
                'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacati' \
                    'on.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth' \
                    '_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DH' \
                    'MAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3D' \
                    'nnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'
            )
        )

        for r in requests:
            req = OAuthRequest(MockRequest((r[0], r[2]), method=r[0], uri=r[1]))
            self.assertEqual(req.signature_base_string(), r[3])

    def testHMAC_SHA1(self):
        from base64 import b64encode
        cases = (
            ('cs', '', 'bs', 'egQqG5AJep5sJ7anhXju1unge2I='),
            ('cs', 'ts', 'bs', 'VZVjXceV7JgPq/dOTnNmEfO0Fv8='),
            ('kd94hf93k423kf44', 'pfkkdhi9sl3r4s00',
                'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file' \
                '%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26' \
                'oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3D' \
                'HMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dn' \
                'nch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal',
                'tR3+Ty81lMeYAr/Fid0kMTYa/WM='),
        )

        for case in cases:
            key = '%s&%s' % (case[0], case[1])
            text = case[2]
            self.assertEqual(b64encode(OAuthSignature_HMAC_SHA1().sign_string(key, text)), case[3])


def diffstring(s1, s2):
    if len(s1) != len(s2):
        print 'Unequal lengths: %s - %s' % (len(s1), len(s2))
        print s1
        print s2
        return

    for i, v in enumerate(s1):
        if v != s2[i]:
            print 'Diff in character %s: %s - %s' % (i, v, s2[i])
