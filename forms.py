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

from cStringIO import StringIO
from PIL import Image

from django import forms
from django.utils.translation import ugettext, ugettext_lazy as _
from django.utils.safestring import mark_safe
from models import Consumer

def seconds_to_string(value):
    months, remaining = divmod(value, 18144000)
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, remaining = divmod(remaining, 60)

    _ = ugettext
    return ', '.join(['%s %s' % (v, s) for v, s in [(months, _('months')),
            (days, _('days')), (hours, _('hours')), (minutes, _('minutes')),
            (remaining, _('seconds'))] if v > 0])

class ConsumerForm(forms.ModelForm):
    image = forms.FileField()
    class Meta:
        model = Consumer
        fields = ('name', 'version', 'consumer_type', 'private', 'developer_email', 'uri', 'description', 'editable_attributes')

    def clean_uri(self):
        uri = self.cleaned_data['uri']
        if not uri.startswith('http://') or uri.startswith('https://'):
            uri = 'http://%s' % uri

        return uri

    def clean_name(self):
        name = self.cleaned_data['name']
        try:
            Consumer.objects.get(name=name)
            raise forms.ValidationError(_('This name is already taken'))
        except Consumer.DoesNotExist:
            return name

    def clean_image(self):
        fobj = self.cleaned_data['image']

        if fobj is None:
            return None

        if fobj.size > 1024 * 1024:
            raise forms.ValidationError(_('This image is too big. Maximum file size is 1 MiB'))
        fobj.seek(0)
        im = Image.open(StringIO(fobj.read()))
        w, h = im.size
        if w < 128 or h < 128:
            raise forms.ValidationError(_('This image is too small. Minimum size is 128x128'))
        if w != h:
            raise forms.ValidationError(_('This image is not square'))

        im.thumbnail((128, 128))
        self.big_image = StringIO()
        im.save(self.big_image, format='PNG')
        self.big_image.seek(0)
        im.thumbnail((64, 64))
        self.small_image = StringIO()
        im.save(self.small_image, format='PNG')
        self.small_image.seek(0)
        fobj.seek(0)

        return fobj

class EditConsumerForm(ConsumerForm):
    image = forms.FileField(required=False)
    class Meta:
        model = Consumer
        fields = ('version', 'uri', 'description', 'private', 'editable_attributes')

class TokenForm(forms.Form):
    oauth_token = forms.CharField(max_length=64, label=_('Token'))
    oauth_callback = forms.CharField(required=False, max_length=1024, widget=forms.HiddenInput())

class TokenAuthorizationForm(forms.Form):
    DURATION_CHOICES = (
        (3600, _('an hour')),
        (86400, _('a day')),
        (604800, _('a week')),
    )
    oauth_token = forms.CharField(max_length=64, widget=forms.HiddenInput())
    oauth_callback = forms.CharField(required=False, max_length=1024, widget=forms.HiddenInput())
    duration = forms.ChoiceField(required=False, label=_('Grant access for'), choices=DURATION_CHOICES)
    renew = forms.BooleanField(required=False)

    def __init__(self, *args, **kwargs):
        super(TokenAuthorizationForm, self).__init__(*args, **kwargs)
        d = self.fields['duration']
        del self.fields['duration']
        r = self.fields['renew']
        del self.fields['renew']
        self.fields['duration'] = d
        self.fields['renew'] = r

    def configure_for_token(self, token):
        self.fields['renew'].label = mark_safe(_('Let %s renew its' \
            ' access permissions (you can cancel them at any time' \
            ' in your settings)') % token.consumer.name)
        # an hour, a day, a week
        if token.duration not in (3600, 86400, 604800):
            self.fields['duration'].choices = [(token.duration, seconds_to_string(token.duration))] + self.fields['duration'].choices

        if not token.consumer.editable_attributes:
            for field in (field for field in self.fields if not field.startswith('oauth_')):
                self.fields[field].widget.attrs.update({'disabled': 'disabled'})

    def default_duration_label(self):
        return self.fields['duration'].choices[0][1]
