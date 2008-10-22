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

from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext as _
from django.utils.safestring import mark_safe
from django.conf import settings

# This allows the notes application to override
# direct_to_template and intercept it for the
# mobile site version
from django.views.generic import simple
direct_to_template = simple.direct_to_template

from storage.models import StoredFile

from oauthsp.models import Consumer, Token, get_token_form
from oauthsp.request import OAuthRequest
from oauthsp.exceptions import OAuthError, OAuthMissingParamError
from oauthsp.paginator import QuerySetPaginator
from forms import *

CONSUMERS_PER_PAGE = 10
CONSUMER_ORDER_MAPPINGS = {
    'newest': '-updated_date',
    'name': 'name',
}

DEFAULT_CONSUMER_ORDER_FIELD = 'newest'

def seconds_to_string(value):
    months, remaining = divmod(value, 18144000)
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, remaining = divmod(remaining, 60)

    return ', '.join(['%s %s' % (v, s) for v, s in [(months, _('months')),
            (days, _('days')), (hours, _('hours')), (minutes, _('minutes')),
            (remaining, _('seconds'))] if v > 0])

def mangle_authorization_form(form, token):
    form.fields['renew'].label = mark_safe(_('Let %s renew its' \
            ' access permissions (you can cancel them at any time' \
            ' in your settings)') % token.consumer.name)
    # an hour, a day, a week
    if token.duration not in (3600, 86400, 604800):
        form.fields['duration'].choices = [(token.duration, seconds_to_string(token.duration))] + form.fields['duration'].choices

    if not token.consumer.editable_attributes:
        for field in (field for field in form.fields if not field.startswith('oauth_')):
            form.fields[field].widget.attrs.update({'disabled': 'disabled'})

@login_required
def new_consumer(request):
    if request.method == 'GET':
        form = ConsumerForm()
        return direct_to_template(request,
            'oauthsp/new_consumer.html',
            locals())

    form = ConsumerForm(request.POST, request.FILES)
    if not form.is_valid():
        return direct_to_template(request,
            'oauthsp/new_consumer.html',
            locals())

    consumer = form.save(commit=False)
    consumer.user = request.user
    consumer.image = StoredFile.store_file('image.png', form.big_image)
    consumer.small_image = StoredFile.store_file('image.png', form.small_image)
    consumer.save()
    return HttpResponseRedirect(consumer.get_absolute_url())

@login_required
def edit_consumer(request, consumer_id):
    consumer = get_object_or_404(Consumer, id=consumer_id)
    if consumer.user != request.user:
        return HttpResponseForbidden(_('Only the consumer owner may edit it'))

    if request.method == 'GET':
        form = EditConsumerForm(initial={
            'version': consumer.version,
            'uri': consumer.uri,
            'description': consumer.description,
            'private': consumer.private,
            'editable_attributes': consumer.editable_attributes,
        })
        return direct_to_template(request,
            'oauthsp/new_consumer.html',
            locals())

    form = EditConsumerForm(request.POST, request.FILES)
    if not form.is_valid():
        return direct_to_template(request,
            'oauthsp/new_consumer.html',
            locals())

    consumer.version = form.cleaned_data['version']
    consumer.uri = form.cleaned_data['uri']
    consumer.description = form.cleaned_data['description']
    consumer.private = form.cleaned_data['private']
    consumer.editable_attributes = form.cleaned_data['editable_attributes']
    for_deletion = []
    if hasattr(form, 'big_image'):
        if consumer.image:
            for_deletion = [consumer.image, consumer.small_image]

        consumer.image = StoredFile.store_file('image.png', form.big_image)
        consumer.small_image = StoredFile.store_file('image.png', form.small_image)
    consumer.save()
    # Delete after changing the foreign keys
    for obj in for_deletion:
        obj.delete()
    return HttpResponseRedirect(consumer.get_absolute_url())

def consumer(request, consumer_id):
    consumer = get_object_or_404(Consumer, id=consumer_id)
    if consumer.private and consumer.user != request.user:
        return HttpResponseForbidden(_('This consumer is private and you are not the owner'))
    return direct_to_template(request, 'oauthsp/consumer.html', locals())

def consumers(request, page):
    ordering = None
    base_url = request.path
    if page:
        base_url = base_url[:-(len(page) + 1)]
    try:
        order_field = CONSUMER_ORDER_MAPPINGS[ordering]
    except KeyError:
        ordering = DEFAULT_CONSUMER_ORDER_FIELD
        order_field = CONSUMER_ORDER_MAPPINGS[ordering]

    cset = Consumer.objects.exclude(private=True).order_by(order_field)
    page = QuerySetPaginator(cset, CONSUMERS_PER_PAGE, base_url=base_url, page_suffix='%d/').page_or_404(page or 1)
    if request.user.is_authenticated():
        user_consumers = Consumer.objects.filter(user=request.user)
    return direct_to_template(request, 'oauthsp/consumers.html', locals())

@login_required
def revoke(request, token_id=None):
    if token_id:
        token = get_object_or_404(Token, id=token_id)
        if token.user != request.user:
            return HttpResponseForbidden(_('This token is not yours'))

        token.delete()

        return HttpResponseRedirect(reverse('revoke'))

    tokens = Token.access.filter(user=request.user)
    return direct_to_template(request, 'oauthsp/revoke.html', locals())

# OAuth token manipulation
def request_token(request):
    try:
        return HttpResponse(OAuthRequest(request).generate_request_token().to_string())
    except OAuthError, e:
        return e.get_response()

@login_required
def authorize(request):
    if request.method == 'GET':
        try:
            token = Token.requested.get(key=request.GET.get('oauth_token'))
            initial = {
                'oauth_token': token.key,
                'oauth_callback': request.REQUEST.get('oauth_callback', ''),
                'duration': token.duration,
            }
            initial.update(token.attrs.as_dict())
            # desktop and mobile clients can renew tokens by default
            if token.consumer.consumer_type in ('D', 'M'):
                initial.update((('renew', True), ))
            form = get_token_form()(initial=initial)
            mangle_authorization_form(form, token)

            return direct_to_template(request,
                'oauthsp/authorize.html', locals())
        except Token.DoesNotExist:
            form = TokenForm(initial=request.GET)
            invalid_token = (request.GET.get('oauth_token') is not None)
            return direct_to_template(request,
                'oauthsp/authorize.html', locals())
    try:
        token = Token.requested.get(key=request.POST.get('oauth_token'))
    except Token.DoesNotExist:
        return HttpResponseRedirect(reverse('authorize-token'))

    form = get_token_form()(request.POST)
    mangle_authorization_form(form, token)
    if not form.is_valid():
        return direct_to_template(request,
            'oauthsp/authorize.html', locals())

    if token.consumer.editable_attributes:
        token.duration = int(form.cleaned_data['duration'])
        token.can_renew = form.cleaned_data['renew']
        token.attrs.copy_from_form(form)

    token.authorize(request.user)
    if form.cleaned_data['oauth_callback']:
        uri = form.cleaned_data['oauth_callback']
        if uri.find('?') < 0:
            fmt = '%s?oauth_token=%s'
        else:
            fmt = '%s&oauth_token=%s'

        return HttpResponseRedirect(fmt % (uri, token.key))

    authorized = True
    return direct_to_template(request, 'oauthsp/authorize.html', locals())

def access_token(request):
    oauth_request = OAuthRequest(request)
    try:
        oauth_request.validate()

        if oauth_request.token is None:
            raise OAuthMissingParamError

        if oauth_request.token.is_access():
            oauth_request.validate_session()
            token = oauth_request.token.renew()
        else:
            token = oauth_request.token.exchange()
        return HttpResponse(token.to_string())
    except OAuthError, e:
        return e.get_response()
