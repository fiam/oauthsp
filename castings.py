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

from django.db import models


"""Casting helpers. Functions are guaranteed
to receive an string and raised ValueErrors
are cached by the caller."""

def get_field_cast(field):
    if isinstance(field, models.IntegerField):
        return integer_cast
    if isinstance(field, models.FloatField):
        return float_cast
    if isinstance(field, models.BooleanField):
        return boolean_cast
    if isinstance(field, models.CharField):
        return get_char_cast(field.max_length)

    raise RunTimeError('"%s" fields are not supported as token attributes' % field.__class__)

def integer_cast(value):
    return int(value)

def float_cast(value):
    return float(value)

def boolean_cast(value):
    if value.lower() in ('true', 't', '1'):
        return True
    if value.lower() in ('false', 'f', '0'):
        return False
    raise ValueError

def get_char_cast(max_length):
    return lambda x: x[:max_length]
