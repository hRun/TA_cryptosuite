#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "encode" used 
    for transforming fields during search time to or from an encoding:
    Base32, Base64, Binary, Charcode, Decimal, Hex, Octal
    
    Author: Harun Kuessner
    Version: 1.0
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from __future__ import absolute_import
from __future__ import print_function

import base64
import binascii
import string
import sys

import splunklib.client as client
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators

@Configuration()
class encodeCommand(EventingCommand):
    """ 
    ##Syntax

    encode mode=(to|from) encoding=(base32|base64|base85|binary|charcode|decimal|hex|octal) <field-list>

    ##Description

    Values of fields provided by `field-list` are transformed using the encoding method specified
    by `encoding`.

    ##Examples

    Decode the content of the field `arg2` from Base64.

    search sourcetype="powershell" | encode mode=from encoding=base64 arg2 | table _time, user, cmd_line, arg*

    """

    mode = Option(
        doc='''
        **Syntax:** **mode=***(to|from)*
        **Description:** whether to transform to or from an encoding''',
        require=False)

    encoding = Option(
        doc='''
        **Syntax:** **encoding=***(base32|base64|base85|binary|charcode|decimal|hex|octal)*
        **Description:** transformation method to use''',
        require=True) 

    py3 = True if sys.version_info >= (3, 0) else False



    ## Helpers for transformation
    #
    def to_base32(self, fieldname, field):
        if self.py3:
            return base64.b32encode(field.encode('utf-8')).decode('utf-8')
        else:
            return base64.b32encode(field)

    def to_base64(self, fieldname, field):
        if self.py3:
            return base64.b64encode(field.encode('utf-8')).decode('utf-8')
        else:
            return base64.b64encode(field)

    def to_base85(self, fieldname, field):
        if self.py3:
            return base64.b85encode(field.encode('utf-8')).decode('utf-8')
        else:
            return # TODO

    def to_binary(self, fieldname, field):
        if self.py3:
            return ''.join([bin(c)[2:].zfill(8) for c in field.encode('utf-8')])
        else:
            return ''.join([bin(ord(c))[2:].zfill(8) for c in field.encode('utf-8')])

    def to_decimal(self, fieldname, field):
        return ' '.join([str(ord(c)) for c in field])

    def to_hex(self, fieldname, field):
        if self.py3:
            return field.encode('utf-8').hex()
        else:
            return binascii.hexlify(field)

    def to_octal(self, fieldname, field):
        if self.py3:
            return ' '.join([str(oct(ord(c)))[2:] for c in field])
        else:
            return ' '.join([str(oct(ord(c)))[1:] for c in field])

    def from_base32(self, fieldname, field):
        if self.py3:
            return ''.join([chr(c) if c in string.printable.encode('utf-8') else '\\{}'.format(str(hex(c))[1:]) for c in base64.b32decode(field.encode('utf-8'))])
        else:
            return ''.join([c if c in string.printable else '\\x{}'.format(hex(ord(c))[2:].zfill(2)) for c in base64.b32decode(field)])

    def from_base64(self, fieldname, field):
        if self.py3:
            return ''.join([chr(c) if c in string.printable.encode('utf-8') else '\\{}'.format(str(hex(c))[1:]) for c in base64.b64decode(field.encode('utf-8'))])
        else:
            return ''.join([c if c in string.printable else '\\x{}'.format(hex(ord(c))[2:].zfill(2)) for c in base64.b64decode(field)])

    def from_base85(self, fieldname, field):
        if self.py3:
            return ''.join([chr(c) if c in string.printable.encode('utf-8') else '\\{}'.format(str(hex(c))[1:]) for c in base64.b85decode(field.encode('utf-8'))])
        else:
            return # TODO

    def from_binary(self, fieldname, field):
        if self.py3:
            return ''.join([chr(c) if c in string.printable.encode('utf-8') else '\\{}'.format(str(hex(c))[1:]) for c in bytes.fromhex('{:02x}'.format(int(field, 2)))])
        else:
            return ''.join([c if c in string.printable else '\\x{}'.format(hex(ord(c))[2:].zfill(2)) for c in binascii.unhexlify('{:02x}'.format(int(field, 2)))])

    def from_decimal(self, fieldname, field):
        if self.py3:
            return ''.join([chr(c) if c in string.printable.encode('utf-8') else '\\{}'.format(str(hex(c))[1:]) for c in (''.join([chr(int(i)) for i in field.split(' ')])).encode('utf-8')])
        else:
            return ''.join([c if c in string.printable else '\\x{}'.format(hex(ord(c))[2:].zfill(2)) for c in ''.join([chr(int(i)) for i in field.split(' ')])])

    def from_hex(self, fieldname, field):
        # Attempt very basic field sanitation so this does not immediately fail on invalid input
        field = ''.join([c for c in field if c in '0123456789abcdef'])
        field = field if len(field)%2 == 0 else field + '0'

        if self.py3:
            return ''.join([chr(c) if c in string.printable.encode('utf-8') else '\\{}'.format(str(hex(c))[1:]) for c in bytes.fromhex(field)])
        else:
            return ''.join([c if c in string.printable else '\\x{}'.format(hex(ord(c))[2:].zfill(2)) for c in binascii.unhexlify(field)])

    def from_octal(self, fieldname, field):
        if self.py3:
            return ''.join([chr(c) if c in string.printable.encode('utf-8') else '\\{}'.format(str(hex(c))[1:]) for c in (''.join([chr(int(i, 8)) for i in field.split(' ')])).encode('utf-8')])
        else:
            return ''.join([c if c in string.printable else '\\x{}'.format(hex(ord(c))[2:].zfill(2)) for c in ''.join([chr(int(i, 8)) for i in field.split(' ')])])



    ## Sort of "__main__"
    #
    def transform(self, events):
        # Set encoding method
        if not self.py3 and self.encoding == 'base85':
            raise RuntimeError('Base85 encoding is not yet supported when running Splunk on Python2.')

        if self.mode == 'to':
            if self.encoding in ['base32', 'base64', 'base85', 'binary', 'decimal', 'hex', 'octal']:
                _encode = getattr(self, 'to_{}'.format(self.encoding))
            else:
                raise ValueError('Invalid encoding method "{0}" specified.'.format(self.encoding))

        elif self.mode == 'from':
            if self.encoding in ['base32', 'base64', 'base85', 'binary', 'decimal', 'hex', 'octal']:
                _encode = getattr(self, 'from_{}'.format(self.encoding))
            else:
                raise ValueError('Invalid encoding method "{0}" specified.'.format(self.encoding))
        else:
            raise ValueError('Invalid mode "{0}" used. Allowed values are "to" and "from".'.format(self.mode))

        # ENCODE
        for event in events:
            for fieldname in self.fieldnames:
                # Always skip _time
                if fieldname == '_time':
                    continue
                try:
                    event[fieldname] = _encode(fieldname, event[fieldname])
                # Return fields where encoding fails "as is", don't throw an error to not cancel the search
                except:
                    pass
            yield event

dispatch(encodeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
