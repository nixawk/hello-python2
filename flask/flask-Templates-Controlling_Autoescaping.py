#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
## Controlling Autoescaping

Autoescaping is the concept of automatically escaping special characters for you.
Special characters in the sense of HTML (or XML, and thus XHTML) are &, >, <, " as well as '.
Because these characters carry specific meanings in documents on their own you have to
replace them by so called “entities” if you want to use them for text.
Not doing so would not only cause user frustration by the inability to
use these characters in text, but can also lead to security problems.
(see Cross-Site Scripting (XSS))

Sometimes however you will need to disable autoescaping in templates.
This can be the case if you want to explicitly inject HTML into pages,
for example if they come from a system that generates secure HTML like
a markdown to HTML converter.

There are three ways to accomplish that:

- In the Python code, wrap the HTML string in a Markup object before passing it to the template.
  This is in general the recommended way.

- Inside the template, use the |safe filter to explicitly mark a string as safe HTML ({{ myvariable|safe }})

- Temporarily disable the autoescape system altogether.

To disable the autoescape system in templates, you can use the {% autoescape %} block:

    {% autoescape false %}
        <p>autoescaping is disabled here
        <p>{{ will_not_be_escaped }}
    {% endautoescape %}

"""