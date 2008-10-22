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

from datetime import datetime, timedelta
from urllib import urlencode
from PIL import Image
import random

from django.conf import settings
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.models import User

from decorators import stored_property
from oauthsp import signatures, exceptions, castings

TOKEN_FORM = None
TOKEN_ATTRS_MODEL = None

def get_token_attrs_model():
    return (TOKEN_ATTRS_MODEL or set_token_attrs_model())

def set_token_attrs_model():
    global TOKEN_ATTRS_MODEL
    if hasattr(settings, 'OAUTH_TOKEN_ATTRS_MODEL') and settings.OAUTH_TOKEN_ATTRS_MODEL:
        app_label, model_name = settings.OAUTH_TOKEN_ATTRS_MODEL.split('.')
        model = models.get_model(app_label, model_name)
        for field in model._meta.local_fields:
            if field.name not in ('id', 'token'):
                model.FIELD_CASTINGS[field.name] = castings.get_field_cast(field)

    else:
        model = EmptyAttributes

    return model

def get_token_form():
    return (TOKEN_FORM or set_token_form())

def set_token_form():
    global TOKEN_FORM
    if not hasattr(settings, 'OAUTH_TOKEN_FORM'):
        from oauthsp.forms import TokenAttributesForm
        TOKEN_FORM = TokenAttributesForm
        return TOKEN_FORM

    try:
        mod_name, form_name = settings.OAUTH_TOKEN_FORM.rsplit('.', 1)
        form = getattr(__import__(mod_name, {}, {}, ['']), form_name)
    except (ImportError, AttributeError, ValueError):
        raise RuntimeError('Cannot import the form for token authorization (%s)' % settings.OAUTH_TOKEN_FORM)

    TOKEN_FORM = form
    return TOKEN_FORM

def random_string(length):
    chars = '01234567890abcdefghijklmnopqrstuvwzyz'
    return ''.join([random.choice(chars) for i in range(length)])

class Consumer(models.Model):
    CONSUMER_TYPE_CHOICES = (
        ('D', _('Desktop client')),
        ('M', _('Mobile client')),
        ('W', _('Web application')),
    )
    user = models.ForeignKey(User)
    key = models.CharField(max_length=32, unique=True, db_index=True)
    secret = models.CharField(max_length=32)
    name = models.CharField(_('Consumer name'), max_length=64)
    version = models.CharField(_('Version'), max_length=20)
    consumer_type = models.CharField(_('Consumer type'), max_length=1, choices=CONSUMER_TYPE_CHOICES)
    private = models.BooleanField(_('Keep this consumer private (only the owner can see it)'), default=False)
    developer_email = models.EmailField(_('Developer email'))
    uri = models.CharField(_('Web'), max_length=255)
    description = models.TextField(_('Description'))
    image_path = models.CharField(_('Image'), max_length=16)
    score = models.FloatField(default=0)
    registration_date = models.DateTimeField(default=datetime.now)
    updated_date = models.DateTimeField()
    editable_attributes = models.BooleanField(_('Let the users modify the requested token attributes'), default=True)

    @models.permalink
    def get_absolute_url(self):
        return ('consumer', [self.id])

    def get_image_url(self, size):
        return '%s%s/%s' % (settings.CONSUMER_IMGS_URL, size, self.image_path)

    def get_small_image_url(self):
        return self.get_image_url(64)

    def get_big_image_url(self):
        return self.get_image_url(128)

    def save(self, *args, **kwargs):
        self.updated_date = datetime.now()
        if not self.key:
            self.key = random_string(32)
            self.secret = random_string(32)
        super(Consumer, self).save(*args, **kwargs)

#class ConsumerVote(models.Model):
#    user = models.ForeignKey(User)
#    consumer = models.ForeignKey(Consumer)
#    value = models.IntegerField()
#    vote_date = models.DateTimeField(default=datetime.now)

class RequestedTokenManager(models.Manager):
    def get_query_set(self):
        return super(RequestedTokenManager, self).get_query_set().filter(token_type='R')

class AuthorizedTokenManager(models.Manager):
    def get_query_set(self):
        return super(AuthorizedTokenManager, self).get_query_set().filter(token_type='S')

class AccessTokenManager(models.Manager):
    def get_query_set(self):
        return super(AccessTokenManager, self).get_query_set().filter(token_type='A')

class Token(models.Model):
    TOKEN_TYPE_CHOICES = (
        ('R', 'request'),
        ('S', 'authorized request'),
        ('A', 'access'),
    )

    key = models.CharField(max_length=32, unique=True, db_index=True)
    secret = models.CharField(max_length=32)
    session_handle = models.CharField(max_length=32)
    consumer = models.ForeignKey(Consumer)
    token_type = models.CharField(max_length=1, choices=TOKEN_TYPE_CHOICES, default='R', db_index=True)
    user = models.ForeignKey(User, null=True, db_index=True)
    creation_date = models.DateTimeField(default=datetime.now)
    duration = models.IntegerField(default=3600)
    expiration_date = models.DateTimeField(null=True, db_index=True)
    can_renew = models.BooleanField(default=False)

    objects = models.Manager()
    requested = RequestedTokenManager()
    authorized = AuthorizedTokenManager()
    access = AccessTokenManager()

    def exchange(self):
        if self.token_type != 'S':
            raise exceptions.OAuthInvalidTokenError('This token is not exchangeable for an access token')

        self.token_type = 'A'
        self.key = random_string(32)
        self.secret = random_string(32)
        self.creation_date = datetime.now()
        self.save()
        return self

    def is_renewable(self):
        return (self.can_renew and self.creation_date +
            timedelta(seconds=2 * self.duration) > datetime.now())

    def renew(self):
        if not self.is_access() or not self.is_renewable():
            raise exceptions.OAuthTokenNotRenewableError

        self.key = random_string(32)
        self.secret = random_string(32)
        self.session_handle = random_string(32)
        self.creation_date = datetime.now()
        self.save()
        return self

    def authorize(self, user):
        self.token_type = 'S'
        self.user = user
        self.save()

    def is_authorized(self):
        return self.token_type == 'S'

    def is_access(self):
        return self.token_type == 'A'

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = random_string(32)
            self.secret = random_string(32)
            self.session_handle = random_string(32)
        self.expiration_date = self.creation_date + timedelta(seconds=self.duration)
        super(Token, self).save(*args, **kwargs)

    @stored_property
    def attrs(self):
        return get_token_attrs_model().for_token(self)

    def to_string(self):
        if self.is_access():
            return urlencode((
                ('oauth_token', self.key),
                ('oauth_token_secret', self.secret),
                ('oauth_session_handle', self.session_handle),
                ('oauth_token_duration', self.duration),
                ('oauth_token_attributes', self.attrs.to_string()),
                ('oauth_token_renewable', str(self.can_renew)),
            ))
        return urlencode((
            ('oauth_token', self.key),
            ('oauth_token_secret', self.secret),
        ))

class Nonce(models.Model):
    consumer = models.ForeignKey(Consumer, db_index=True)
    token = models.ForeignKey(Token, null=True, db_index=True)
    value = models.CharField(max_length=64, db_index=True)

    def save(self, *args, **kwargs):
        self.value = self.value[:64]
        super(Nonce, self).save(*args, **kwargs)

class Attributes(models.Model):
    class Meta:
        abstract = True

    FIELD_CASTINGS = {}

    token = models.ForeignKey(Token)

    def clean(self):
        pass

    def save(self, *args, **kwargs):
        self.clean()
        super(Attributes, self).save(*args, **kwargs)

    def copy_from_form(self, form):
        for key in self.__class__.FIELD_CASTINGS:
            setattr(self, key, form.cleaned_data[key])
        self.save()

    def set_field_value(self, fieldname, value):
        try:
            setattr(self, fieldname, self.__class__.FIELD_CASTINGS[fieldname](value))
        except (KeyError, ValueError), e:
            pass

    def set_attributes(self, attrs):
        try:
            for item in attrs.split(';'):
                field, value = item.split(':', 1)
                self.set_field_value(field, value)
            self.save()
        except (TypeError, AttributeError):
            pass

    def to_string(self):
        return ';'.join(['%s:%s' % (key, getattr(self, key)) for key in self.__class__.FIELD_CASTINGS])

    def as_dict(self):
        return dict([(k, getattr(self, k)) for k in self.__class__.FIELD_CASTINGS])

    @classmethod
    def for_token(cls, token):
        return cls.objects.get_or_create(token=token)[0]

class EmptyAttributes(object):
    def __init__(self, *args, **kwargs):
        super(EmptyAttributes, self).__init__(*args, **kwargs)

    def save(self, *args, **kwargs):
        pass

    def copy_from_form(self, form):
        pass

    def set_attributes(self, attrs):
        pass

    def to_string(self):
        return u''

    @classmethod
    def for_token(cls, token):
        return EmptyAttributes()

