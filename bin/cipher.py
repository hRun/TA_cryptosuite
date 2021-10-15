#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "cipher" used 
    for ciphering and deciphering fields during search time using algorithms 
    which are generally regarded as cryptographically insecure: RC4, ROT-13, ROT-47, XOR
    
    Author: Harun Kuessner
    Version: 1.0
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from __future__ import absolute_import
from __future__ import print_function

import base64
import binascii
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import splunklib.client as client
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators



@Configuration()
class cipherCommand(EventingCommand):
    """ 
    ##Syntax

    cipher mode=(e|d) algorithm=(rc4|rot13|rot47|xor) key=<string> <field-list>

    ##Description

    Values of fields provided by `field-list` are ciphered or deciphered with
    the key provided by `key` and the algorithm specified by `algorithm` depending on the mode set by `mode`.

    Currently supported algorithms are RC4, ROT-13, ROT-47 and XOR.

    ##Requirements

    Properly deployed key files and properly configured permissions to use these key files.
    See README.md.

    ##Examples

    Decipher the values of field "payload" which is extracted from a DNS query.

    search index="dns" type="query" | rex field=query "(?<payload>[^\.]*?)\." | cipher mode=d algorithm=rc4 key="r3coveredK3y." payload

    En-/Decrypt the values of field "message" using XOR.

    search sourcetype="ctf" | cipher mode=e algorithm=xor key="\x2f" message
    """



    mode = Option(
        doc='''
        **Syntax:** **mode=***(d|e)*
        **Description:** d for deciphering or e for ciphering''',
        require=True)

    algorithm = Option(
        doc='''
        **Syntax:** **algorithm=***(rc4|rot13|rot47|xor)*
        **Description:** cryptographic algorithm to use''',
        require=True)    

    key = Option(
        doc='''
        **Syntax:** **key=***<string>*
        **Description:** ascii representation of the key to use''',
        require=True)

    py3 = True if sys.version_info >= (3, 0) else False



    ## Helpers for ciphering and deciphering
    #
    def rc4_encrypt(self, fieldname, field, key):
        try:
            if len(key)%2 != 0 or len(key) < 2 or len(key)/2 > 256:
                raise ValueError()
            for c in key:
                if c not in '0123456789abcdef':
                    raise ValueError()
            key = bytes.fromhex(key) if self.py3 else [ord(k) for k in binascii.unhexlify(key)]
        except ValueError:
            raise ValueError('Value for "key" must be a valid hex string (no delimiters) between 1 and 256 bytes length for RC4 operations! E.g. "41", "01ea4f".')

        try:
            S = list(range(256))
            j = 0

            for i in range(256): # Key Scheduling Algorithm (KSA)
                j          = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]

            i, j, c = 0, 0, ''

            for p in field.encode('utf-8'):
                i          = (i + 1) % 256
                j          = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                c         += '{:02x}'.format(p ^ S[(S[i] + S[j]) % 256]) if self.py3 else '{}'.format(hex(ord(p) ^ S[(S[i] + S[j]) % 256])[2:].zfill(2))
            return c
        except:
            return field

    def rot13_encrypt(self, fieldname, field, key):
        try:
            key = int(key)
        except ValueError:
            raise ValueError('Value for "key" must be an integer for ROT operations!')

        try:
            cipher = []
            for i in range(len(field)):
                unicode_repr = ord(field[i])
                if unicode_repr >= 65 and unicode_repr <= 90: # A-Z
                    cipher.append(chr(65 + ((unicode_repr + key - 65) % 26)))
                elif unicode_repr >= 97 and unicode_repr <= 122: # a-z
                    cipher.append(chr(97 + ((unicode_repr + key - 97) % 26)))
                else: # Skip characters outside the ASCII ranges
                    cipher.append(field[i])
            return ''.join(cipher)
        except:
            return field

    def rot47_encrypt(self, fieldname, field, key):
        try:
            key = int(key)
        except ValueError:
            raise ValueError('Value for "key" must be an integer for ROT operations!')

        try:
            cipher = []
            for i in range(len(field)):
                unicode_repr = ord(field[i])
                if unicode_repr >= 33 and unicode_repr <= 126:
                    cipher.append(chr(33 + ((unicode_repr + key - 33) % 94)))
                else: # Skip characters outside the ASCII range
                    cipher.append(field[i])
            return ''.join(cipher)
        except:
            return field

    def xor_encrypt(self, fieldname, field, key):
        try:
            if len(key)%2 != 0:
                raise ValueError()
            for c in key:
                if c not in '0123456789abcdef':
                    raise ValueError()
        except ValueError:
            raise ValueError('Value for "key" must be a valid hex string (no delimiters) for XOR operations! E.g. "41", "01ea4f".')

        try:
            if self.py3:
                if len(bytes.fromhex(key)) == 1:
                    key = bytes.fromhex(key) * len(field.encode('utf-8'))
                elif len(field.encode('utf-8')) == len(bytes.fromhex(key)):
                    key = bytes.fromhex(key)
                elif len(field.encode('utf-8')) < len(bytes.fromhex(key)):
                    key = bytes.fromhex(key)[0:len(field.encode('utf-8'))]
                elif len(field.encode('utf-8')) > len(bytes.fromhex(key)):
                    key = bytes.fromhex(key) * (len(field.encode('utf-8'))%len(bytes.fromhex(key))) + bytes.fromhex(key)[0:len(field.encode('utf-8'))-len(bytes.fromhex(key) * (len(field.encode('utf-8'))%len(bytes.fromhex(key))))]
                return ''.join(['{:02x}'.format(m^k) for m, k in zip(field.encode('utf-8'), key)])
            else:
                if len(binascii.unhexlify(key)) == 1:
                    key = binascii.unhexlify(key) * len(field.encode('utf-8'))
                elif len(field.encode('utf-8')) == len(binascii.unhexlify(key)):
                    key = binascii.unhexlify(key)
                elif len(field.encode('utf-8')) < len(binascii.unhexlify(key)):
                    key = binascii.unhexlify(key)[0:len(field.encode('utf-8'))]
                elif len(field.encode('utf-8')) > len(binascii.unhexlify(key)):
                    key = binascii.unhexlify(key) * (len(field.encode('utf-8'))%len(binascii.unhexlify(key))) + binascii.unhexlify(key)[0:len(field.encode('utf-8'))-len(binascii.unhexlify(key) * (len(field.encode('utf-8'))%len(binascii.unhexlify(key))))]
                return ''.join(['{}'.format(hex(ord(m)^ord(k)))[2:].zfill(2) for m, k in zip(field, key)])
        except:
            return field

    def rc4_decrypt(self, fieldname, field, key):
        try:
            if len(key)%2 != 0 or len(key) < 2 or len(key)/2 > 256:
                raise ValueError()
            for c in key:
                if c not in '0123456789abcdef':
                    raise ValueError()
            key = bytes.fromhex(key) if self.py3 else [ord(k) for k in binascii.unhexlify(key)]
        except ValueError:
            raise ValueError('Value for "key" must be a valid hex string (no delimiters) between 1 and 256 bytes length for RC4 operations! E.g. "41", "01ea4f".')

        try:
            if len(field)%2 != 0:
                raise ValueError()
            for c in field:
                if c not in '0123456789abcdef':
                    raise ValueError()
            field = bytes.fromhex(field) if self.py3 else binascii.unhexlify(field)
        except ValueError:
            #raise ValueError('Field values must be valid hex strings (no delimiters) for RC4 decryption! E.g. "41", "01ea4f". Please use RC4 encryption otherwise.')
            return field

        try:
            S = list(range(256))
            j = 0

            for i in range(256): # Key Scheduling ALgorithm (KSA)
                j          = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]

            i, j, c = 0, 0, ''

            for p in field:
                i          = (i + 1) % 256
                j          = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                c         += bytes.fromhex('{:02x}'.format(p ^ S[(S[i] + S[j]) % 256])).decode('utf-8') if self.py3 else '{}'.format(chr(ord(p) ^ S[(S[i] + S[j]) % 256]))
            return c
        except:
            return field.hex() if self.py3 else binascii.hexlify(field)

    def rot13_decrypt(self, fieldname, field, key):
        try:
            key = int(key)
        except ValueError:
            raise ValueError('Value for "key" must be an integer for ROT operations!')

        try:
            cipher = []
            for i in range(len(field)):
                unicode_repr = ord(field[i])
                if unicode_repr >= 65 and unicode_repr <= 90: # A-Z
                    cipher.append(chr(65 + ((unicode_repr - key - 65) % 26)))
                elif unicode_repr >= 97 and unicode_repr <= 122: # a-z
                    cipher.append(chr(97 + ((unicode_repr - key - 97) % 26)))
                else: # Skip characters outside the ASCII ranges
                    cipher.append(field[i])
            return ''.join(cipher)
        except:
            return field

    def rot47_decrypt(self, fieldname, field, key):
        try:
            key = int(key)
        except ValueError:
            raise ValueError('Value for "key" must be an integer for ROT operations!')

        try:
            cipher = []
            for i in range(len(field)):
                unicode_repr = ord(field[i])
                if unicode_repr >= 33 and unicode_repr <= 126:
                    cipher.append(chr(33 + ((unicode_repr - key - 33) % 94)))
                else: # Skip characters outside the ASCII range
                    cipher.append(field[i])
            return ''.join(cipher)
        except:
            return field

    def xor_decrypt(self, fieldname, field, key):
        try:
            if len(key)%2 != 0:
                raise ValueError()
            for c in key:
                if c not in '0123456789abcdef':
                    raise ValueError() 
        except ValueError:
            raise ValueError('Value for "key" must be a valid hex string (no delimiters) for XOR operations! E.g. "41", "01ea4f".')

        try:
            if len(field)%2 != 0:
                raise ValueError()
            for c in field:
                if c not in '0123456789abcdef':
                    raise ValueError()
            field = bytes.fromhex(field) if self.py3 else binascii.unhexlify(field)
        except ValueError:
            #raise ValueError('Field values must be valid hex strings (no delimiters) for XOR decryption! E.g. "41", "01ea4f". Please use XOR encryption otherwise.')
            return field

        try:
            if self.py3:
                if len(bytes.fromhex(key)) == 1:
                    key = bytes.fromhex(key) * len(field)
                elif len(field) == len(bytes.fromhex(key)):
                    key = bytes.fromhex(key)
                elif len(field) < len(bytes.fromhex(key)):
                    key = bytes.fromhex(key)[0:len(field)]
                elif len(field) > len(bytes.fromhex(key)):
                    key = bytes.fromhex(key) * (len(field)%len(bytes.fromhex(key))) + bytes.fromhex(key)[0:len(field)-len(bytes.fromhex(key) * (len(field)%len(bytes.fromhex(key))))]
                return bytes.fromhex(''.join(['{:02x}'.format(m^k) for m, k in zip(field, key)])).decode('utf-8')
            else:
                if len(binascii.unhexlify(key)) == 1:
                    key = binascii.unhexlify(key) * len(field)
                elif len(field) == len(binascii.unhexlify(key)):
                    key = binascii.unhexlify(key)
                elif len(field) < len(binascii.unhexlify(key)):
                    key = binascii.unhexlify(key)[0:len(field)]
                elif len(field) > len(binascii.unhexlify(key)):
                    key = binascii.unhexlify(key) * (len(field)%len(binascii.unhexlify(key))) + binascii.unhexlify(key)[0:len(field)-len(binascii.unhexlify(key) * (len(field)%len(binascii.unhexlify(key))))]
                return ''.join(['{}'.format(chr(ord(m)^ord(k))) for m, k in zip(field, key)])
        except:
            return field.hex() if self.py3 else binascii.hexlify(field)



    ## Sort of "__main__"
    #
    def transform(self, events):
        # Set cipher algorithm
        if self.mode == 'e':
            if self.algorithm in ['rc4', 'rot13', 'rot47', 'xor']:
                _cipher = getattr(self, '{}_encrypt'.format(self.algorithm))
            else:
                raise ValueError('Invalid or unsupported algorithm specified: "{0}".'.format(self.algorithm))

        elif self.mode == 'd':
            if self.algorithm in ['rc4', 'rot13', 'rot47', 'xor']:
                _cipher = getattr(self, '{}_decrypt'.format(self.algorithm))
            else:
                raise ValueError('Invalid or unsupported algorithm specified: "{0}".'.format(self.algorithm))
        else:
            raise ValueError('Invalid mode "{0}" used. Allowed values are "e" and "d".'.format(self.mode))

        # CIPHER or DECIPHER
        #
        for event in events:
            for fieldname in self.fieldnames:
                # Always skip _time
                if fieldname == '_time':
                    continue
                event[fieldname] = _cipher(fieldname, event[fieldname], self.key)
            yield event

dispatch(cipherCommand, sys.argv, sys.stdin, sys.stdout, __name__)
