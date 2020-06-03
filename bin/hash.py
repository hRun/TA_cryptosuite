#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "hash" used 
    for hashing fields during search time using the common hashing 
    algorithms MD5, SHA1, SHA224, SHA256, SHA384, SHA512.
    
    Author: Harun Kuessner
    Version: 2.0a
    License: http://creativecommons.org/licenses/by-nc-sa/4.0/
"""

from __future__ import absolute_import
from __future__ import print_function

import base64
import hashlib
import sys
import re

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class hashCommand(StreamingCommand):
    """ 
    ##Syntax

    hash algorithm=<md5|sha1|sha224|sha256|sha384|sha512> [saltfile=<file_name>] <field-list>

    ##Description
    
    Values of fields provided by `field-list` are hashed using the algorithm specified
    by `algorithm`. Optionally the salt stored in `saltfile` is applied.
    
    Currently supported algorithms for field hashing are are MD5, SHA1, SHA224, SHA256, SHA384, SHA512.
          
    ##Examples

    Hash the content of the field `body` using SHA256 and apply the salt stored in secret.txt.
    
    search sourcetype="apache::data" | hash algoritm=sha256 saltfile=secret.txt body
          
    """

    algorithm = Option(
        doc='''
        **Syntax:** **algorithm=***<md5|sha1|sha224|sha256|sha384|sha512>*
        **Description:** hashing algorithm to use''',
        require=True) 

    saltfile = Option(
        doc='''
        **Syntax:** **saltfile=***<file_name>*
        **Description:** file which holds the salt to use''',
        require=False) 

    def stream(self, events):

        # Get salt if saltfile was provided
        #
        if self.saltfile:
            try:
                if __file__.startswith('/'):
                    path = __file__.split('/')
                    path.pop()
                    path.pop()
                    path.extend(['lib', 'salts', '{}'.format(self.saltfile)])
                    f = open('/'.join(path), 'r')
                else:
                    path = __file__.split('\\')
                    path.pop()
                    path.pop()
                    path.extend(['lib', 'salts', '{}'.format(self.saltfile)])
                    f = open('\\'.join(path), 'r')
                salt = f.readline()
                f.close()
            except Exception as e:
                self.logger.error('Failed to open specified salt file: {0}'.format(e))
                return

        # Perform field hashing
        #
        for event in events:
            for fieldname in self.fieldnames:
                if fieldname == '_time':
                    continue
                try:
                    if self.saltfile:
                        if self.algorithm == 'md5':
                            event[self.algorithm] = hashlib.md5(salt.encode('utf-8') + event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha1':
                            event[self.algorithm] = hashlib.sha1(salt.encode('utf-8') + event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha224':
                            event[self.algorithm] = hashlib.sha224(salt.encode('utf-8') + event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha256':
                            event[self.algorithm] = hashlib.sha256(salt.encode('utf-8') + event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha384':
                            event[self.algorithm] = hashlib.sha384(salt.encode('utf-8') + event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha512':
                            event[self.algorithm] = hashlib.sha512(salt.encode('utf-8') + event[fieldname].encode('utf-8')).hexdigest()
                        else:
                            raise RuntimeWarning('Invalid hash algorithm {0} has been specified.'.format(self.algorithm))
                    else:
                        if self.algorithm == 'md5':
                            event[self.algorithm] = hashlib.md5(event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha1':
                            event[self.algorithm] = hashlib.sha1(event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha224':
                            event[self.algorithm] = hashlib.sha224(event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha256':
                            event[self.algorithm] = hashlib.sha256(event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha384':
                            event[self.algorithm] = hashlib.sha384(event[fieldname].encode('utf-8')).hexdigest()
                        elif self.algorithm == 'sha512':
                            event[self.algorithm] = hashlib.sha512(event[fieldname].encode('utf-8')).hexdigest()
                        else:
                            raise RuntimeWarning('Invalid hash algorithm {0} has been specified.'.format(self.algorithm))
                except Exception as e:
                    self.logger.error('Failed to hash fields: {0}'.format(e))
            yield event

dispatch(hashCommand, sys.argv, sys.stdin, sys.stdout, __name__)
