#!/usr/bin/env python

""" 
    Implementation of the custom Splunk> search command "hash" used
    for hashing fields during search time using the common hashing 
    algorithms MD5, SHA1, SHA224, SHA256, SHA384, SHA512.
    
    Author: Harun Kuessner
    Version: 1.0
"""

import sys, base64, re
import hashlib
from splunklib.searchcommands import \
     dispatch, StreamingCommand, Configuration, Option, validators

@Configuration()
class HashCommand(StreamingCommand):
    """ 
    ##Syntax

    hash algorithm=<md5|sha1|sha224|sha256|sha384|sha512> [saltfile=<file_path>] <field-list>

    ##Description
    
    Values of fields provided by `field-list` are hashed using the algorithm specified
    by `algorithm`. Optionally the salt stored in `saltfile` is applied.
    
    Currently supported algorithms for field hashing are are  MD5, SHA1, SHA224, SHA256, SHA384, SHA512.
          
    ##Examples

    Hash the content of the field `body` using SHA256 and apply the salt stored in splunk.secret.
    
    search sourcetype="apache::data" | hash algoritm=sha256 saltfile=/opt/splunk/etc/auth/splunk.secret body
          
    """
    
    algorithm = Option(
        doc='''
        **Syntax:** **algorithm=***<md5|sha1|sha224|sha256|sha384|sha512>*
        **Description:** hashing algorithm''',
        require=True) 
  
    saltfile = Option(
        doc='''
        **Syntax:** **saltfile=***<path_to_file>*
        **Description:** file which holds the salt to use''',
        require=False, validate=validators.File()) 
        
    def stream(self, records):

      # Get Salt if saltfile was provided
      #
      if self.saltfile:
          salt = self.saltfile.read()
      
      # Perform field hashing
      #
      for record in records:
          for fieldname in self.fieldnames:
              if fieldname=='_time':
                  continue     
              try:
                  if self.saltfile:
                      if self.algorithm and re.match(r'md5', self.algorithm):
                          record[fieldname] = hashlib.md5(salt + record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha1', self.algorithm):
                          record[fieldname] = hashlib.sha1(salt + record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha224', self.algorithm):
                          record[fieldname] = hashlib.sha224(salt + record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha256', self.algorithm):
                          record[fieldname] = hashlib.sha256(salt + record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha384', self.algorithm):
                          record[fieldname] = hashlib.sha384(salt + record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha512', self.algorithm):
                          record[fieldname] = hashlib.sha512(salt + record[fieldname]).hexdigest()
                      else:
                          raise RuntimeWarning('Invalid hash algorithm %s has been specified.' % str(self.algorithm))
                  else:
                      if self.algorithm and re.match(r'md5', self.algorithm):
                          record[fieldname] = hashlib.md5(record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha1', self.algorithm):
                          record[fieldname] = hashlib.sha1(record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha224', self.algorithm):
                          record[fieldname] = hashlib.sha224(record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha256', self.algorithm):
                          record[fieldname] = hashlib.sha256(record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha384', self.algorithm):
                          record[fieldname] = hashlib.sha384(record[fieldname]).hexdigest()
                      elif self.algorithm and re.match(r'sha512', self.algorithm):
                          record[fieldname] = hashlib.sha512(record[fieldname]).hexdigest()
                      else:
                          raise RuntimeWarning('Invalid hash algorithm %s has been specified.' % str(self.algorithm))
              except:
                  raise
          yield record

dispatch(HashCommand, sys.argv, sys.stdin, sys.stdout, __name__)