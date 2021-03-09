#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "hash" used 
    for hashing fields during search time using the common hashing 
    algorithms MD5, SHA1, SHA2 (224, 256, 384, 512), SHA3 (224, 256, 384, 512), Blake2.
    
    Author: Harun Kuessner
    Version: 2.1
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from __future__ import absolute_import
from __future__ import print_function

import hashlib
import json
import sys

import splunklib.client as client
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators

@Configuration()
class hashCommand(EventingCommand):
    """ 
    ##Syntax

    hash algorithm=(md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|blake2b|blake2s) (salt=<string>)? <field-list>

    ##Description
    
    Values of fields provided by `field-list` are hashed using the algorithm specified
    by `algorithm`. Optionally the salt stored in `salt` is applied.
    
    MD5, SHA1 and SHA2 hashing algorithms are supported for both Python 2 and 3.
    
    SHA3 and Blake2 hashing algorithms are only supported when using Python 3 as Splunk's interpreter.
          
    ##Examples

    Hash the content of the field `body` using SHA256 and the salt configured for name "secret.txt".
    
    search sourcetype="apache::data" | hash algoritm=sha256 salt=secret.txt body
          
    """

    algorithm = Option(
        doc='''
        **Syntax:** **algorithm=***(md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|blake2b|blake2s)*
        **Description:** hashing algorithm to use''',
        require=True) 

    salt = Option(
        doc='''
        **Syntax:** **salt=***<string>*
        **Description:** configuration which holds the salt to use''',
        require=False)




    ## Helper to check if a user is privileged to do what he is trying to do
    #
    def validate_user(self, service):
        auth_roles = []
        auth_users = []
        user       = self._metadata.searchinfo.username
        roles      = []

        try:
            auth_roles = service.confs['inputs']['crypto_settings://{0}'.format(self.salt)]['authorized_roles'].split('~')
        except AttributeError:
            pass
        try:
            auth_users = service.confs['inputs']['crypto_settings://{0}'.format(self.salt)]['authorized_users'].split('~')
        except AttributeError:
            pass

        for role in service.users[self._metadata.searchinfo.username]['role_entities']:
            roles.append(role.name)
            for imported_role in role.imported_roles:
                roles.append(imported_role)

        if user in auth_users:
            return True
        else:
            for role in roles:
                if role in auth_roles:
                    return True

        return False



    ## Helper to load salts
    #
    def load_salt(self, service):
        stored_salt = service.storage_passwords.list(count=-1, search='data/inputs/crypto_settings:'.format(self.salt))
        salt_dict   = ""

        for chunk in stored_salt:
            salt_dict += chunk.clear_password
        salt_dict = json.loads(salt_dict.split('``splunk_cred_sep``', 1)[0])
        return salt_dict['key_salt']



    ## Sort of "__main__"
    #
    def transform(self, events):
        # Bind to Splunk session and initialize variables
        service = client.Service(token=self.metadata.searchinfo.session_key)
        salt    = ""

        # Get salt if "salt" was set
        if self.salt:
            # Check if configuration exists for specified salt
            try:
                service.confs['inputs']['crypto_settings://{0}'.format(self.salt)]
            except:
                raise ValueError('Specified salt file "{0}" does not exist. Please check the spelling of your specified salt name or your configured salts.'.format(self.salt))

            # Continue if user is authorized for salt usage
            if self.validate_user(service):
                salt = self.load_salt(service)

        # HASH
        #
        for event in events:
            for fieldname in self.fieldnames:
                if fieldname == '_time':
                    continue
                try:
                    if self.salt:
                        message = salt.encode('utf-8') + event[fieldname].encode('utf-8')
                    else:
                        message = event[fieldname].encode('utf-8')

                    if self.algorithm in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
                        hashmethod            = getattr(hashlib, self.algorithm)
                        event[self.algorithm] = hashmethod(message).hexdigest()
                    elif sys.version_info >= (3, 0) and self.algorithm in ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'blake2b', 'blake2s']:
                        hashmethod            = getattr(hashlib, self.algorithm)
                        event[self.algorithm] = hashmethod(message).hexdigest()
                    elif sys.version_info < (3, 0) and self.algorithm in ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'blake2b', 'blake2s']:
                        raise RuntimeWarning('Hash algorithm "{0}" is only available when using Python 3 as Splunk\'s Python interpreter.'.format(self.algorithm))
                    else:
                        raise ValueError('Invalid hash algorithm "{0}" has been specified.'.format(self.algorithm))
                except Exception as e:
                    raise RuntimeWarning('Failed to hash fields: {0}'.format(e))
            yield event

dispatch(hashCommand, sys.argv, sys.stdin, sys.stdout, __name__)
