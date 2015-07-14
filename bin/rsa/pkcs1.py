# -*- coding: utf-8 -*-
#
#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

'''Functions for PKCS#1 version 1.5 encryption and signing

This module implements certain functionality from PKCS#1 version 1.5. For a
very clear example, read http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

At least 8 bytes of random padding is used when encrypting a message. This makes
these methods much more secure than the ones in the ``rsa`` module.

WARNING: this module leaks information when decryption or verification fails.
The exceptions that are raised contain the Python traceback information, which
can be used to deduce where in the process the failure occurred. DO NOT PASS
SUCH INFORMATION to your users.
'''

'''Modified by Harun Kuessner.
   Added methods for encryption without random padding for proper function 
   of the custom Splunk 'crypt' command.
'''

import os

from rsa._compat import b
from rsa import common, transform, core, varblock

class CryptoError(Exception):
    '''Base class for all exceptions in this module.'''

class DecryptionError(CryptoError):
    '''Raised when decryption fails.'''
 
def _pad_random(message, target_length):
    r'''Pads the message for encryption, returning the padded message.
    
    :return: 00 02 RANDOM_DATA 00 MESSAGE
    
    >>> block = _pad_for_encryption('hello', 16)
    >>> len(block)
    16
    >>> block[0:2]
    '\x00\x02'
    >>> block[-6:]
    '\x00hello'

    '''

    max_msglength = target_length - 11
    msglength = len(message)
    
    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only'
            ' space for %i' % (msglength, max_msglength))
    
    # Get random padding
    padding = b('')
    padding_length = target_length - msglength - 3
    
    # We remove 0-bytes, so we'll end up with less padding than we've asked for,
    # so keep adding data until we're at the correct length.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        
        # Always read at least 8 bytes more than we need, and trim off the rest
        # after removing the 0-bytes. This increases the chance of getting
        # enough bytes, especially when needed_bytes is small
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b('\x00'), b(''))
        padding = padding + new_padding[:needed_bytes]
        
    assert len(padding) == padding_length
    
    return b('').join([b('\x00\x02'),
                    padding,
                    b('\x00'),
                    message])

def _pad_zero(message, target_length):
    r'''Pads the message for encryption, returning the padded message.
    
    :return: 00 02 ZERO_BYTES 00 MESSAGE

    '''

    max_msglength = target_length - 11
    msglength = len(message)
    
    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only'
            ' space for %i' % (msglength, max_msglength))
    
    # Get random padding
    padding = b('')
    padding_length = target_length - msglength - 3
    
    # We remove 0-bytes, so we'll end up with less padding than we've asked for,
    # so keep adding data until we're at the correct length.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        
        # Always read at least 8 bytes more than we need, and trim off the rest
        # after removing the 0-bytes. This increases the chance of getting
        # enough bytes, especially when needed_bytes is small
        new_padding = b('\xff')
        for i in range(1,needed_bytes):
            new_padding = new_padding + b('\xff')
        padding = padding + new_padding[:needed_bytes]
        
    assert len(padding) == padding_length
    
    return b('').join([b('\x00\x02'),
                    padding,
                    b('\x00'),
                    message])   

def encrypt_rand_padding(message, pub_key):
    '''Encrypts the given message using PKCS#1 v1.5
    
    :param message: the message to encrypt. Must be a byte string no longer than
        ``k-11`` bytes, where ``k`` is the number of bytes needed to encode
        the ``n`` component of the public key.
    :param pub_key: the :py:class:`rsa.PublicKey` to encrypt with.
    :raise OverflowError: when the message is too large to fit in the padded
        block.
        
    >>> from rsa import key, common
    >>> (pub_key, priv_key) = key.newkeys(256)
    >>> message = 'hello'
    >>> crypto = encrypt(message, pub_key)
    
    The crypto text should be just as long as the public key 'n' component:

    >>> len(crypto) == common.byte_size(pub_key.n)
    True
    
    '''
    
    keylength = common.byte_size(pub_key.n)
    padded = _pad_random(message, keylength)
    
    payload = transform.bytes2int(padded)
    encrypted = core.encrypt_int(payload, pub_key.e, pub_key.n)
    block = transform.int2bytes(encrypted, keylength)
    
    return block
    
def encrypt_zero_padding(message, pub_key):
    '''Encrypts the given message without random padding    
    '''
    
    keylength = common.byte_size(pub_key.n)
    padded = _pad_zero(message, keylength)
    
    payload = transform.bytes2int(padded)
    encrypted = core.encrypt_int(payload, pub_key.e, pub_key.n)
    block = transform.int2bytes(encrypted, keylength)
    
    return block

def decrypt(crypto, priv_key):
    r'''Decrypts the given message using PKCS#1 v1.5
    
    The decryption is considered 'failed' when the resulting cleartext doesn't
    start with the bytes 00 02, or when the 00 byte between the padding and
    the message cannot be found.
    
    :param crypto: the crypto text as returned by :py:func:`rsa.encrypt`
    :param priv_key: the :py:class:`rsa.PrivateKey` to decrypt with.
    :raise DecryptionError: when the decryption fails. No details are given as
        to why the code thinks the decryption fails, as this would leak
        information about the private key.


    >>> import rsa
    >>> (pub_key, priv_key) = rsa.newkeys(256)

    It works with strings:

    >>> crypto = encrypt('hello', pub_key)
    >>> decrypt(crypto, priv_key)
    'hello'
    
    And with binary data:

    >>> crypto = encrypt('\x00\x00\x00\x00\x01', pub_key)
    >>> decrypt(crypto, priv_key)
    '\x00\x00\x00\x00\x01'

    Altering the encrypted information will *likely* cause a
    :py:class:`rsa.pkcs1.DecryptionError`. If you want to be *sure*, use
    :py:func:`rsa.sign`.


    .. warning::

        Never display the stack trace of a
        :py:class:`rsa.pkcs1.DecryptionError` exception. It shows where in the
        code the exception occurred, and thus leaks information about the key.
        It's only a tiny bit of information, but every bit makes cracking the
        keys easier.

    >>> crypto = encrypt('hello', pub_key)
    >>> crypto = crypto[0:5] + 'X' + crypto[6:] # change a byte
    >>> decrypt(crypto, priv_key)
    Traceback (most recent call last):
    ...
    DecryptionError: Decryption failed

    '''
    
    blocksize = common.byte_size(priv_key.n)
    encrypted = transform.bytes2int(crypto)
    decrypted = core.decrypt_int(encrypted, priv_key.d, priv_key.n)
    cleartext = transform.int2bytes(decrypted, blocksize)

    # If we can't find the cleartext marker, decryption failed.
    if cleartext[0:2] != b('\x00\x02'):
        raise DecryptionError('Decryption failed')
    
    # Find the 00 separator between the padding and the message
    try:
        sep_idx = cleartext.index(b('\x00'), 2)
    except ValueError:
        raise DecryptionError('Decryption failed')
    
    return cleartext[sep_idx+1:]
    
