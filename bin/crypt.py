#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "crypt" used 
    for encrypting and decrypting fields during search time using RSA or AES.
    
    Author: Harun Kuessner
    Version: 2.5.0
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""


import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import splunklib.client as client
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators


AES_ALGORITHMS = [
    'aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
    'aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb',
]


@Configuration()
class cryptCommand(EventingCommand):
    """ 
    ##Syntax

    crypt mode=(e|d) algorithm=(rsa|aes-cbc|aes-ofb) key=<string> (ivfield=<field>)? (ivextract=<field>)? <field-list>

    ##Description
    
    Values of fields provided by `field-list` are encrypted or decrypted with
    the key provided by `key` and the algorithm specified by `algorithm` depending on the mode set by `mode`.
    
    Currently supported cryptographic algorithms are RSA and AES-CBC, AES-OFB (with 128/192/256 bit keys).
    
    Encrypted private RSA keys are supported if encrypted with AES256-CBC, DES-CBC or DES-EDE3-CBC.

    For AES, the IV may come from the configured key file (default), from `ivfield`
    (a field holding the IV), or from `ivextract` (first 16 bytes of a base64-decoded
    field, typically prepended to the ciphertext). `ivfield` and `ivextract` are
    mutually exclusive and take precedence over a configured IV when present.

    ##Requirements

    Properly deployed key files and properly configured permissions to use these key files.
    See README.md.

    ##Examples

    Encrypt the values of the plaintext fields "subject" and "content" of sourcetype "mail" using rsa and the key "public.pem".
    
    search sourcetype="mail" | crypt mode=e algorithm=rsa key=public.pem subject content
    
    Encrypt raw events of sourcetype "mail" using AES-256-CBC and collect the results in a summary index.
    
    search sourcetype="mail" | crypt mode=e algorithm=aes-cbc key=secret.txt _raw | collect index=summary
    
    Decrypt the content of the already RSA encrypted and summary-indexed field "username" for output in plain text using RSA. 
    The key file "private.pem" is encrypted with AES-256-CBC, so the correspondig password has to be set via the app's set up screen prior to using the key.
    
    search index=summary sourcetype="server::access" | crypt mode=d algorithm=rsa key=private.pem username | table _time action username

    Decrypt a Vector-style AES-256-CBC payload where a per-message IV is prepended to the ciphertext before Base64 encoding.

    search sourcetype="vector" | crypt mode=d algorithm=aes-cbc key=vector_key ivextract=payload payload
    """


    mode = Option(
        doc='''
        **Syntax:** **mode=***(d|e)*
        **Description:** d for decryption or e for encryption''',
        require=True)

    algorithm = Option(
        doc='''
        **Syntax:** **algorithm=***(rsa|aes-128-cbc|aes-192-cbc|aes-256-cbc)*
        **Description:** cryptographic algorithm to use''',
        require=True)    

    key = Option(
        doc='''
        **Syntax:** **key=***<string>*
        **Description:** name of the file containing the cryptographic key to use''',
        require=True)

    ivfield = Option(
        doc='''
        **Syntax:** **ivfield=***<fieldname>*
        **Description:** field holding the AES IV (hex, base64, or 16 raw bytes). Takes precedence over a configured IV. Mutually exclusive with ivextract.''',
        require=False,
        validate=validators.Fieldname())

    ivextract = Option(
        doc='''
        **Syntax:** **ivextract=***<fieldname>*
        **Description:** field whose base64-decoded value starts with a 16-byte AES IV (prepended to ciphertext). Takes precedence over a configured IV. Mutually exclusive with ivfield.''',
        require=False,
        validate=validators.Fieldname())

    module = False # Flag for pycryptodomex usage


    def use_dynamic_iv(self):
        return bool(self.ivfield or self.ivextract)


    def parse_iv(self, value):
        """
        Parse a 16-byte AES IV from hex, base64, or raw ASCII.
        """
        if value is None:
            raise ValueError('IV value is missing.')

        value = str(value).strip()

        if not value:
            raise ValueError('IV value is empty.')

        # Hex (32 hex chars = 16 bytes)
        if len(value) == 32 and all(c in '0123456789abcdefABCDEF' for c in value):
            iv = bytes.fromhex(value)
            if len(iv) == 16:
                return iv

        # Base64
        try:
            iv = base64.decodebytes(value.encode('utf-8'))
            if len(iv) == 16:
                return iv
        except Exception:
            pass

        # Raw 16-byte ASCII/UTF-8
        raw = value.encode('utf-8')
        if len(raw) == 16:
            return raw

        raise ValueError('IV must be 16 bytes (hex, base64, or raw).')


    def validate_user(self, service):
        """
        Helper to check if a user is privileged to do what they are trying to do
        """
        user, roles, auth_users, auth_roles = self._metadata.searchinfo.username, [], [], []

        try:
            auth_roles = service.confs['inputs'][f'crypto_settings://{self.key}']['authorized_roles'].split('~')
        except AttributeError:
            pass
        try:
            auth_users = service.confs['inputs'][f'crypto_settings://{self.key}']['authorized_users'].split('~')
        except AttributeError:
            pass

        for role in service.users[self._metadata.searchinfo.username]['role_entities']:
            roles.append(role.name)
            for imported_role in role.imported_roles:
                roles.append(imported_role)

        if self.mode == 'e' and not 'can_encrypt' in roles:
            raise RuntimeWarning(f'User "{user}" is not authorized to perform field encryption.')
        if self.mode == 'd' and not 'can_decrypt' in roles:
            raise RuntimeWarning(f'User "{user}" is not authorized to perform field decryption.')

        if user in auth_users:
            return True
        else:
            for role in roles:
                if role in auth_roles:
                    return True
        return False


    def load_key(self, service):
        """
        Helper to load keys and run basic review checks
        """
        stored_keys = service.storage_passwords.list(count=-1, search=f'data/inputs/crypto_settings:')
        key_dict   = ''.join([chunk.clear_password if f'data/inputs/crypto_settings:{self.key}`' in chunk.name else '' for chunk in stored_keys])

        if not key_dict.startswith('{'):
            key_dict = json.loads(''.join(key_dict.split('``splunk_cred_sep``', 1)[::-1]).split('``splunk_cred_sep``')[-1])
        else:
            key_dict = json.loads(key_dict.split('``splunk_cred_sep``', 1)[0])

        if self.algorithm == 'rsa':
            if not key_dict['key_salt'].startswith('-----BEGIN RSA '):
                raise RuntimeWarning('Currently only RSA keys in PEM format are supported. Please specify a valid key file.')

            # Load RSA public key
            if self.mode == 'e':
                if not ' PUBLIC KEY-----' in key_dict['key_salt']:
                    raise RuntimeWarning('Only public RSA keys in PEM format are supported. Please specify a valid public key file.')
                if len(key_dict['key_salt'].strip('\n').split('-----')[-3]) < 220:
                    raise RuntimeWarning('1024 bit RSA keys are generally considered insecure and are therefore unsupported. Please use a larger key.')

                try:
                    key = "-----BEGIN RSA PUBLIC KEY-----\n"
                    for i in range(0, len(''.join(key_dict['key_salt'].split('-----')[2])), 64):
                        key += f"{''.join(key_dict['key_salt'].split('-----')[2])[i:i+64]}\n"
                    key += "-----END RSA PUBLIC KEY-----"
                    if self.module:
                        return RSA.import_key(key.encode('utf-8')), None
                    else:
                        return rsa.key.PublicKey.load_pkcs1(key.encode('utf-8'), 'PEM'), None
                except Exception as e:
                    raise RuntimeWarning(f'Failed to load specified public key: {e}.')

            # Load RSA private key
            else:
                if not ' PRIVATE KEY-----' in key_dict['key_salt']:
                    raise RuntimeWarning('Only private RSA keys in PEM format are supported. Please specify a valid private key file.')
                if len(key_dict['key_salt'].strip('\n').split('-----')[-3]) < 824:
                    raise RuntimeWarning('1024 bit RSA keys are generally considered insecure and are therefore unsupported. Please use a larger key.')

                try:
                    if 'DEK-Info:' in key_dict['key_salt'] and 'rsa_key_encryption_password' not in key_dict:
                        raise RuntimeWarning('No password was configured for encrypted private key. Please configure one before using this key.')
                    elif 'DEK-Info:' in key_dict['key_salt'] and not self.module:
                        raise RuntimeWarning('Use of encrypted private RSA keys is only supported if the "pycryptodomex" python package is installed and configured via the app\'s setup screen.')
                    elif 'DEK-Info:' in key_dict['key_salt'] and self.module:
                        key = ' '.join(key_dict['key_salt'].split(' ')[0:4]) + '\n' + ' '.join(key_dict['key_salt'].split(' ')[4:6]) + '\n' + ' '.join(key_dict['key_salt'].split(' ')[6:8]) + '\n\n'
                        for i in range(0, len(''.join(key_dict['key_salt'].split('-----')[2].split(' ')[5::])), 64):
                            key += f"{''.join(key_dict['key_salt'].split('-----')[2].split(' ')[5::])[i:i+64]}\n"
                        key += "-----END RSA PRIVATE KEY-----"
                        return RSA.import_key(key.encode('utf-8'), passphrase=key_dict['rsa_key_encryption_password'].encode('utf-8')), None
                    else:
                        key = "-----BEGIN RSA PRIVATE KEY-----\n"
                        for i in range(0, len(''.join(key_dict['key_salt'].split('-----')[2])), 64):
                            key += f"{''.join(key_dict['key_salt'].split('-----')[2])[i:i+64]}\n"
                        key += "-----END RSA PRIVATE KEY-----"
                        if self.module:
                            return RSA.import_key(key.encode('utf-8')), None
                        else:
                            return rsa.key.PrivateKey.load_pkcs1(key.encode('utf-8'), 'PEM'), None
                except Exception as e:
                    raise RuntimeWarning(f'Failed to load specified private key: {e}')

        # Load AES key and IV
        elif self.algorithm in AES_ALGORITHMS:
            material = key_dict['key_salt'].strip(' \r\n')

            try:
                # Key-only material when IV comes from log events
                if self.use_dynamic_iv():
                    # hex key only
                    if len(material) == 64 and all(c in '0123456789abcdefABCDEF' for c in material):
                        return bytes.fromhex(material), None
                    elif len(material) == 48 and all(c in '0123456789abcdefABCDEF' for c in material):
                        return bytes.fromhex(material), None
                    elif len(material) == 32 and all(c in '0123456789abcdefABCDEF' for c in material):
                        return bytes.fromhex(material), None
                    # plaintext key only
                    elif len(material) == 32:
                        return material, None
                    elif len(material) == 24:
                        return material, None
                    elif len(material) == 16:
                        return material, None
                    # key+IV files remain valid; use key portion only
                    elif len(material) in [96, 97, 98]:
                        return bytes.fromhex(material[0:64]), None
                    elif len(material) in [80, 81, 82]:
                        return bytes.fromhex(material[0:48]), None
                    elif len(material) in [64, 65, 66]:
                        return bytes.fromhex(material[0:32]), None
                    elif len(material) in [48, 49, 50]:
                        return material[0:32], None
                    elif len(material) in [40, 41, 42]:
                        return material[0:24], None
                    else:
                        raise ValueError('Key does not have the correct length. Key must be 16, 24 or 32 bytes.')

                # Return hex key + IV from storage
                if len(material) in [96, 97, 98]:
                    key = bytes.fromhex(material[0:64])
                    iv  = bytes.fromhex(material[-32::])
                elif len(material) in [80, 81, 82]:
                    key = bytes.fromhex(material[0:48])
                    iv  = bytes.fromhex(material[-32::])
                elif len(material) in [64, 65, 66]:
                    key = bytes.fromhex(material[0:32])
                    iv  = bytes.fromhex(material[-32::])
                # plaintext key + IV
                elif len(material) in [48, 49, 50]:
                    key = material[0:32]
                    iv  = material[-16::]
                elif len(material) in [40, 41, 42]:
                    key = material[0:24]
                    iv  = material[-16::]
                elif len(material) in [32, 33, 34]:
                    key = material[0:16]
                    iv  = material[-16::]
                else:
                    raise ValueError('Key and/or IV do not have the correct length. Key must be 16, 24 or 32 bytes. IV must be 16 bytes.')
                return key, iv
            except Exception as e:
                raise RuntimeWarning(f'Failed to load AES key and/or IV: {e}.')

        else:
            raise ValueError(f'Invalid or unsupported algorithm specified: {self.algorithm}.')


    def rsa_encrypt(self, fieldname, field, key, iv=None):
        """
        Helpers for encryption and decryption
        """
        # Split fields bigger than 214 bytes
        if len(field) > 214:
            try:
                if self.module:
                    return ''.join([base64.encodebytes(PKCS1_OAEP.new(key).encrypt(field[i:i+214].encode('utf-8'))).decode('utf-8') for i in range(0, len(field), 214)])
                else:
                    return ''.join([base64.encodebytes(rsa.OAEP_encrypt(field[i:i+214].encode('utf-8'), key)).decode('utf-8') for i in range(0, len(field), 214)])
            except Exception as e:
                raise RuntimeWarning(f'Encryption failed for field "{fieldname}". Reason: {e}')
        # Otherwise encrypt straight forward
        else:
            try:
                if self.module:
                    return base64.encodebytes(PKCS1_OAEP.new(key).encrypt(field.encode('utf-8'))).decode('utf-8')
                else:
                    return base64.encodebytes(rsa.OAEP_encrypt(field.encode('utf-8'), key)).decode('utf-8')
            except Exception as e:
                raise RuntimeWarning(f'Encryption failed for field "{fieldname}". Reason: {e}')


    def rsa_decrypt(self, fieldname, field, key, iv=None):
        # Rejoin fields split into blocks during encryption
        if len(field.replace('\n', '')) > 344:
            try:
                if self.module:
                    return ''.join([PKCS1_OAEP.new(key).decrypt(base64.decodebytes(''.join([chunk.replace('\n', ''), '==']).encode('utf-8'))).decode('utf-8') for chunk in field.split('==') if len(chunk)>1])
                else:
                    return ''.join([rsa.OAEP_decrypt(base64.decodebytes(''.join([chunk.replace('\n', ''), '==']).encode('utf-8')), key).decode('utf-8') for chunk in field.split('==') if len(chunk)>1])
            except Exception as e:
                raise RuntimeWarning(f'Decryption failed for field "{fieldname}". Reason: {e}')
        # Otherwise decrypt straight forward
        else:
            try:
                if self.module:
                    return PKCS1_OAEP.new(key).decrypt(base64.decodebytes(field.replace('\n', '').encode('utf-8'))).decode('utf-8')
                else:
                    return rsa.OAEP_decrypt(base64.decodebytes(field.replace('\n', '').encode('utf-8')), key).decode('utf-8')
            except Exception as e:
                raise RuntimeWarning(f'Decryption failed for field "{fieldname}". Reason: {e}')


    def _aes_encrypt_bytes(self, field, key, iv):
        """Return raw ciphertext bytes (no base64)."""
        if type(key) == str:
            key = key.encode('utf-8')
        if type(iv) == str:
            iv = iv.encode('utf-8')

        if self.algorithm in ['aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']:
            if self.module:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                return cipher.encrypt(pad(field.encode('utf-8'), AES.block_size))

            encryptor    = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
            cipher_text  = encryptor.feed(field.encode('utf-8'))
            cipher_text += encryptor.feed()
            return cipher_text

        if self.algorithm in ['aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']:
            if self.module:
                cipher = AES.new(key, AES.MODE_OFB, iv)
                return cipher.encrypt(field.encode('utf-8'))

            aes = pyaes.AESModeOfOperationOFB(key, iv=iv)
            return aes.encrypt(field.encode('utf-8'))

        raise ValueError(f'Invalid or unsupported algorithm specified: {self.algorithm}.')


    def _aes_decrypt_bytes(self, cipher_text, key, iv):
        """Decrypt raw ciphertext bytes to plaintext string."""
        if type(key) == str:
            key = key.encode('utf-8')
        if type(iv) == str:
            iv = iv.encode('utf-8')

        if self.algorithm in ['aes-cbc', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc']:
            if self.module:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                return unpad(cipher.decrypt(cipher_text), AES.block_size).decode('utf-8')

            decryptor = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
            plain_text = decryptor.feed(cipher_text)
            plain_text += decryptor.feed()
            return plain_text.decode('utf-8')

        if self.algorithm in ['aes-ofb', 'aes-128-ofb', 'aes-192-ofb', 'aes-256-ofb']:
            if self.module:
                cipher = AES.new(key, AES.MODE_OFB, iv)
                return cipher.decrypt(cipher_text).decode('utf-8')

            aes = pyaes.AESModeOfOperationOFB(key, iv=iv)
            return aes.decrypt(cipher_text).decode('utf-8')

        raise ValueError(f'Invalid or unsupported algorithm specified: {self.algorithm}.')


    def aes_encrypt(self, fieldname, field, key, iv, prepend_iv=False):
        try:
            cipher_text = self._aes_encrypt_bytes(field, key, iv)
            if prepend_iv:
                return base64.encodebytes(iv + cipher_text).decode('utf-8')
            return base64.encodebytes(cipher_text).decode('utf-8')
        except Exception as e:
            raise RuntimeWarning(f'Encryption failed for field "{fieldname}". Reason: {e}')


    def aes_decrypt(self, fieldname, field, key, iv, cipher_bytes=None):
        try:
            if cipher_bytes is None:
                cipher_bytes = base64.decodebytes(field.encode('utf-8'))
            return self._aes_decrypt_bytes(cipher_bytes, key, iv)
        except Exception as e:
            raise RuntimeWarning(f'Decryption failed for field "{fieldname}". Reason: {e}')


    def transform(self, events):     
        # Bind to Splunk session and initialize variables
        service = client.Service(token=self.metadata.searchinfo.session_key)

        if self.ivfield and self.ivextract:
            raise ValueError('Options "ivfield" and "ivextract" are mutually exclusive. Specify only one.')
        if self.use_dynamic_iv() and self.algorithm not in AES_ALGORITHMS:
            raise ValueError('Options "ivfield" and "ivextract" are only supported with AES algorithms.')

        # Check if configuration exists for specified key
        try:
            service.confs['inputs'][f'crypto_settings://{self.key}']
        except Exception:
            raise ValueError(f'Specified key file "{self.key}" does not exist. Please check the spelling of your specified key name or your configured keys.')

        # Configuration agnostic imports
        try:
            sys.path.append(service.confs['ta_cryptosuite_settings']['additional_parameters']['site_packages'])
            global AES, PKCS1_OAEP, RSA, pad, unpad
            from Cryptodome.Cipher import AES, PKCS1_OAEP
            from Cryptodome.PublicKey import RSA
            from Cryptodome.Util.Padding import pad, unpad
            self.module = True
        except Exception:
            global pyaes, rsa
            import pyaes
            import rsa
            self.module = False

        # ENCRYPTION
        if self.mode == 'e':
            # Continue if user is authorized for encryption and key usage
            if self.validate_user(service):
                # Set encryption method
                if self.algorithm == 'rsa':
                    _encrypt = self.rsa_encrypt
                elif self.algorithm in AES_ALGORITHMS:
                    _encrypt = self.aes_encrypt
                else:
                    raise ValueError(f'Invalid or unsupported algorithm specified: {self.algorithm}.')

                # Load key and do review checks
                key, configured_iv = self.load_key(service)

                # Perform field encryption
                for event in events:
                    # Resolve AES IV once per event when using dynamic IV options
                    event_iv = configured_iv

                    if self.algorithm in AES_ALGORITHMS:
                        if self.ivfield:
                            if self.ivfield not in event:
                                raise RuntimeWarning(f'IV field "{self.ivfield}" is missing from the event.')
                            event_iv = self.parse_iv(event[self.ivfield])
                        elif self.ivextract:
                            event_iv = os.urandom(16)

                    for fieldname in self.fieldnames:
                        # Always skip _time
                        if fieldname == '_time':
                            continue

                        if self.algorithm in AES_ALGORITHMS:
                            prepend_iv = bool(self.ivextract and fieldname == self.ivextract)
                            event[fieldname] = self.aes_encrypt(fieldname, event[fieldname], key, event_iv, prepend_iv=prepend_iv)
                        else:
                            event[fieldname] = _encrypt(fieldname, event[fieldname], key, configured_iv)
                    yield event
            else:
                raise RuntimeWarning(f'User "{self._metadata.searchinfo.username}" is not authorized to use the specified encryption key.')

        # DECRYPTION
        elif self.mode == 'd':
            # Continue if user is authorized for decryption and key usage
            if self.validate_user(service):
                # Set decryption mode
                if self.algorithm == 'rsa':
                    _decrypt = self.rsa_decrypt
                elif self.algorithm in AES_ALGORITHMS:
                    _decrypt = self.aes_decrypt
                else:
                    raise ValueError(f'Invalid or unsupported algorithm specified: {self.algorithm}.')

                # Load key and do review checks
                key, configured_iv = self.load_key(service)

                # Perform field decryption
                for event in events:
                    # Resolve AES IV once per event when using dynamic IV options
                    event_iv = configured_iv
                    extract_cipher_bytes = None

                    if self.algorithm in AES_ALGORITHMS:
                        if self.ivfield:
                            if self.ivfield not in event:
                                raise RuntimeWarning(f'IV field "{self.ivfield}" is missing from the event.')
                            event_iv = self.parse_iv(event[self.ivfield])
                        elif self.ivextract:
                            if self.ivextract not in event:
                                raise RuntimeWarning(f'IV extract field "{self.ivextract}" is missing from the event.')

                            try:
                                raw = base64.decodebytes(str(event[self.ivextract]).replace('\n', '').encode('utf-8'))
                            except Exception as e:
                                raise RuntimeWarning(f'Failed to base64-decode field "{self.ivextract}" for IV extraction: {e}')

                            if len(raw) < 16:
                                raise RuntimeWarning(f'Field "{self.ivextract}" is too short to contain a 16-byte IV.')

                            event_iv = raw[:16]
                            extract_cipher_bytes = raw[16:]

                    for fieldname in self.fieldnames:
                        if fieldname == '_time':
                            continue

                        if self.algorithm in AES_ALGORITHMS:
                            cipher_bytes = extract_cipher_bytes if fieldname == self.ivextract else None
                            event[fieldname] = self.aes_decrypt(fieldname, event[fieldname], key, event_iv, cipher_bytes=cipher_bytes)
                        else:
                            event[fieldname] = _decrypt(fieldname, event[fieldname], key, configured_iv)
                    yield event
            else:
                raise RuntimeWarning(f'User "{self._metadata.searchinfo.username}" is not authorized to use the specified decryption key.')

        else:
            raise ValueError(f'Invalid mode "{self.mode}" used. Allowed values are "e" and "d".')


dispatch(cryptCommand, sys.argv, sys.stdin, sys.stdout, __name__)
