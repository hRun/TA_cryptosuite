#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "encode" used 
    for transforming fields during search time to or from an encoding:
    Base32, Base58, Base62, Base64, Binary, Charcode, Decimal, Hex, Octal
    
    Author: Harun Kuessner
    Version: 1.2
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from base58 import base58
from base62 import base62

import base64
import os
import string
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import splunklib.client as client
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators

@Configuration()
class encodeCommand(EventingCommand):
    """ 
    ##Syntax

    encode mode=(to|from) encoding=(base32|base58|base62|base64|base85|binary|charcode|decimal|hex|octal) <field-list>

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
        **Syntax:** **encoding=***(base32|base58|base62|base64|base85|binary|charcode|decimal|hex|octal)*
        **Description:** transformation method to use''',
        require=True) 



    ## Helpers for transformation
    #
    def to_base32(self, fieldname, field):
        return base64.b32encode(field.encode('utf-8')).decode('utf-8')

    def to_base58(self, fieldname, field):
        return base58.b58encode(field.encode('utf-8')).decode('utf-8')

    def to_base62(self, fieldname, field):
        return base62.b62encode(field.encode('utf-8'))

    def to_base64(self, fieldname, field):
        return base64.b64encode(field.encode('utf-8')).decode('utf-8')

    def to_base85(self, fieldname, field):
        return base64.b85encode(field.encode('utf-8')).decode('utf-8')

    def to_binary(self, fieldname, field):
        return ''.join([bin(c)[2:].zfill(8) for c in field.encode('utf-8')])

    def to_decimal(self, fieldname, field):
        return ' '.join([str(ord(c)) for c in field])

    def to_hex(self, fieldname, field):
        return field.encode('utf-8').hex()

    def to_octal(self, fieldname, field):
        return ' '.join([str(oct(ord(c)))[2:] for c in field])

    def from_base32(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in base64.b32decode(field.encode('utf-8'))])

    def from_base58(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in base58.b58decode(field.encode('utf-8'))])

    def from_base62(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in base62.b62decode(field)])

    def from_base64(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in base64.b64decode(field.encode('utf-8'))])

    def from_base85(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in base64.b85decode(field.encode('utf-8'))])

    def from_binary(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in bytes.fromhex(f'{int(field, 2):02x}')])

    def from_decimal(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in (''.join([chr(int(i)) for i in field.split(' ')])).encode('utf-8')])

    def from_hex(self, fieldname, field):
        # Attempt very basic field sanitation so this does not immediately fail on invalid input
        field = ''.join([c for c in field if c in '0123456789abcdef'])
        field = field if len(field)%2 == 0 else field + '0'

        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in bytes.fromhex(field)])

    def from_octal(self, fieldname, field):
        return ''.join([chr(c) if c in string.printable.encode('utf-8') else f'\\{hex(c)[1:]}' for c in (''.join([chr(int(i, 8)) for i in field.split(' ')])).encode('utf-8')])



    ## Sort of "__main__"
    #
    def transform(self, events):
        # Set encoding method
        if self.mode == 'to':
            if self.encoding in ['base32', 'base58', 'base62', 'base64', 'base85', 'binary', 'decimal', 'hex', 'octal']:
                _encode = getattr(self, f'to_{self.encoding}')
            else:
                raise ValueError(f'Invalid encoding method "{self.encoding}" specified.')

        elif self.mode == 'from':
            if self.encoding in ['base32', 'base58', 'base62', 'base64', 'base85', 'binary', 'decimal', 'hex', 'octal']:
                _encode = getattr(self, f'from_{self.encoding}')
            else:
                raise ValueError(f'Invalid encoding method "{self.encoding}" specified.')
        else:
            raise ValueError(f'Invalid mode "{self.mode}" used. Allowed values are "to" and "from".')

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
