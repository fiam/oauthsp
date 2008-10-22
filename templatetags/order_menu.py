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

from django import template

register = template.Library()

@register.tag
def order_menu(parser, token):
    try:
        tag, request, ordering = token.split_contents()
    except ValueError:
        raise template.TemplateSyntaxError('%s tag requires 2 argument' % token.split_contents()[0])

    return OrderMenuNode(request, ordering)

ORDERINGS = (
    (_('Last updated'), 'newest'),
    (_('Name'), 'name'),
)

def get_url(request, ordering, new_ordering):

class OrderMenuNode(template.Node):
    def __init__(self, request):
        self.request = template.Variable(request)
        self.ordering = template.Variable(ordering)
    
    def render(self, context):
        markup = [u'<ul>']
        request = self.request.resolve(context)
        ordering = self.ordering.resolve(context)
        for ord in ORDERINGS:
            if ord[1] == ordering:
                markup.append(u'<li><a class="current">%s</a></li>' % ugettext(ord[0])) 
            else:
                markup.append(u'<li><a href="%s">%s</a></li>' % (get_url(request, ord[1]), ugettext(ord[0]))) 
        
