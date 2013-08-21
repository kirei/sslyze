#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         CertParser.py
# Purpose:      Utility classes for parsing certificates. Used by the plugins
#               to extract relevant fields, URIs etc.
#
# Author:       joachims
#
# Copyright:    2012 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import re
from xml.etree.ElementTree import Element


class X509CertificateHelper:
    """
    Helper functions for X509 certificate parsing and XML serialization.
    """
    
    def __init__(self, certificate):
        self._cert = certificate

        
    def parse_certificate(self):
        cert_dict = \
            {'version': self._cert.get_version().split('(')[0].strip() ,
             'serialNumber': self._cert.get_serial_number() ,
             'issuer': self._cert.get_issuer_name().get_all_entries() ,
             'validity': {'notBefore': self._cert.get_not_before() ,
                         'notAfter' : self._cert.get_not_after()} ,
             'subject': self._cert.get_subject_name().get_all_entries() ,
             'subjectPublicKeyInfo':{'publicKeyAlgorithm': self._cert.get_pubkey_algorithm() ,
                                     'publicKeySize': str( self._cert.get_pubkey_size()*8) ,
                                     'publicKey': {'modulus': self._cert.get_pubkey_modulus_as_text(),
                                                   'exponent': self._cert.get_pubkey_exponent_as_text()}
                                     },
             'extensions': self._get_all_extensions() ,
             'signatureAlgorithm': self._cert.get_signature_algorithm() ,
             'signatureValue': self._cert.get_signature_as_text() }
        
        return cert_dict
        

    def parse_certificate_to_xml(self):
        cert_dict = self.parse_certificate()
        cert_xml = []
        
        for (key, value) in cert_dict.items():
            for xml_elem in self._keyvalue_pair_to_xml(key, value):
                cert_xml.append(xml_elem)
 
        return cert_xml
            

    def _create_xml_node(self, key, value=''):
        key = key.replace(' ', '').strip() # Remove spaces
        key = key.replace('/', '').strip() # Remove slashes (S/MIME Capabilities)
        
        # Things that would generate invalid XML
        if key[0].isdigit(): # Tags cannot start with a digit
                key = 'oid-' + key 
                
        xml_node = Element(key)
        xml_node.text = value.decode( "utf-8" ).strip()
        return xml_node
    
    
    def _keyvalue_pair_to_xml(self, key, value=''):
        res_xml = []
        
        if type(value) is str: # value is a string
            key_xml = self._create_xml_node(key)
            key_xml.text = value
            res_xml.append(key_xml)
            
        elif value is None: # no value
            res_xml.append(self._create_xml_node(key))
           
        elif type(value) is list: # multiple strings
            for val in value:
                res_xml.append(self._create_xml_node(key, val))
           
        elif type(value) is dict: # value is a list of subnodes
            key_xml = self._create_xml_node(key)
            for subkey in value.keys():
                for subxml in self._keyvalue_pair_to_xml(subkey, value[subkey]):
                    key_xml.append(subxml)
                 
            res_xml.append(key_xml)
            
        return res_xml    


    def _parse_multi_valued_extension(self, extension):
        extension = extension.split(', ')
        # Split the (key,value) pairs
        parsed_ext = {}
        for value in extension:
            value = value.split(':', 1)
            if len(value) == 1:
                parsed_ext[value[0]] = ''
            else:
                if parsed_ext.has_key(value[0]):
                    parsed_ext[value[0]].append(value[1])
                else:
                    parsed_ext[value[0]] = [value[1]]

        return parsed_ext
        
    
    def _parse_authority_information_access(self, auth_ext):
        # Hazardous attempt at parsing an Authority Information Access extension
        auth_ext = auth_ext.strip(' \n').split('\n')
        auth_ext_list = {}
         
        for auth_entry in auth_ext:
            auth_entry = auth_entry.split(' - ')
            entry_name = auth_entry[0].replace(' ', '')

            if not auth_ext_list.has_key(entry_name):
                auth_ext_list[entry_name] = {}
            
            entry_data = auth_entry[1].split(':', 1)
            if auth_ext_list[entry_name].has_key(entry_data[0]):
                auth_ext_list[entry_name][entry_data[0]].append(entry_data[1])
            else:
                auth_ext_list[entry_name] = {entry_data[0]: [entry_data[1]]}
                
        return auth_ext_list
            
              
    def _parse_crl_distribution_points(self, crl_ext):
        # Hazardous attempt at parsing a CRL Distribution Point extension
        crl_ext = crl_ext.strip(' \n').split('\n')
        subcrl = {}

        for distrib_point in crl_ext:
            distrib_point = distrib_point.strip()
            distrib_point = distrib_point.split(':', 1)
            if distrib_point[0] != '':
                if subcrl.has_key(distrib_point[0].strip()):
                    subcrl[distrib_point[0].strip()].append(distrib_point[1].strip())
                else:
                    subcrl[distrib_point[0].strip()] = [(distrib_point[1].strip())]

        return subcrl
        
                
    def _get_all_extensions(self):
        ext_dict = self._cert.get_extension_list().get_all_extensions()

        parsing_functions = {'X509v3 Subject Alternative Name': self._parse_multi_valued_extension,
                             'X509v3 CRL Distribution Points': self._parse_crl_distribution_points,
                             'Authority Information Access': self._parse_authority_information_access,
                             'X509v3 Key Usage': self._parse_multi_valued_extension,
                             'X509v3 Extended Key Usage': self._parse_multi_valued_extension,
                             'X509v3 Certificate Policies' : self._parse_crl_distribution_points,
                             'X509v3 Issuer Alternative Name' : self._parse_crl_distribution_points}
        
        for (ext_key, ext_val) in ext_dict.items():
            # Overwrite the data we have if we know how to parse it
            if ext_key in parsing_functions.keys():
                ext_dict[ext_key] = parsing_functions[ext_key](ext_val)

        return ext_dict


def _dnsname_to_pat(dn):
    """
    Generates a regexp for the given name, to be used for hostname validation
    Taken from http://pypi.python.org/pypi/backports.ssl_match_hostname/3.2a3
    """
    pats = []
    for frag in dn.split(r'.'):
        if frag == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        else:
            # Otherwise, '*' matches any dotless fragment.
            frag = re.escape(frag)
            pats.append(frag.replace(r'\*', '[^.]*'))
    return re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)
