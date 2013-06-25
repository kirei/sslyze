#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginHTTPvsHTTPS.py
# Purpose:      Compare the content received from the server over
#               HTTP vs HTTPS.
#
#               Currently the checking is expected to be done separately using
#               https-everywhere-checker.
#               https://github.com/hiviah/https-everywhere-checker
#
#               This Plugin simply checks that it can connect to the server
#               via HTTP and HTTPS. If that is possible, the plugin generates
#               a customized rule for the server.
#
# Author:       joachims
#
# Copyright:    2013 SSLyze developers
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

from plugins import PluginBase
from xml.etree.ElementTree import Element
import httplib
import ssl
import os

RULE_DIR = os.path.join(os.path.dirname(PluginBase.__file__), 'rules')

class PluginHTTPvsHTTPS(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHTTPvsHTTPS", description=(''))
    interface.add_command(
        command="httpvshttps",
        help="Generate rules to https everywhere checker to compare the content "
             "provided by the server via HTTP vs HTTPS.",
        dest=None)

    def process_task(self, target, command, args):

        output_format = '        {0:<25} {1}'

        (host, addr, port) = target

        self.http_error = None
        self.https_error = None

        self.http_connection = httplib.HTTPConnection(host, 80)
        try:
            self.http_connection.connect()
            self.http_connection.request("HEAD", "/", headers={"Connection": "close"})
            self.http_response = self.http_connection.getresponse()
            self.http_headers = self.http_response.getheaders()
        except httplib.HTTPException as self.http_error:
            pass
        finally:
            self.http_connection.close()

        self.https_connection = httplib.HTTPSConnection(host, 443)
        try:
            self.https_connection.connect()
            self.https_connection.request("HEAD", "/", headers={"Connection": "close"})
            self.https_response = self.https_connection.getresponse()
            self.https_headers = self.https_response.getheaders()
        except ssl.SSLError as self.https_error:
            pass
        finally:
            self.https_connection.close()

        # If we could connect to the host using both
        # http and https we generate a rule for the host.
        if not self.http_error and not self.https_error:
            self.rule_filename = RULE_DIR + '/' + host + '.xml'
            with open(self.rule_filename, 'wb') as self.rule_file:
                self.rule_file.write('<!-- Generated by sslyze plugin HTTPvsHTTPS. -->\n')
                self.rule_file.write('<ruleset name="' + host + '">\n')
                self.rule_file.write('  <target host="' + host + '" />\n')
                if not 'www.' in host:
                    self.rule_file.write('  <target host="' + 'www.' + host + '" />\n')
                    self.rule_file.write('  <rule from="^http://(www\.)?' + host +\
                                         '/"' + ' to="https://' + 'www.' + host + '" />\n')
                else:
                    self.rule_file.write('  <rule from="^http://?' + host +\
                                         '/"' + ' to="https://' + host + '" />\n')
                self.rule_file.write('</ruleset>\n')


        # Generate diagnostic info in text and XML format.
        cmd_title = 'HTTP vs HTTPS'
        self.txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        if not self.http_error and not self.https_error:
            self.txt_result.append(output_format.format("HTTP and HTTPS supported.", ""))
        else:
            if self.http_error:
                self.txt_result.append(output_format.format("HTTP not supported.", ""))
            if self.https_error:
                self.txt_result.append(output_format.format("HTTPS not supported.", ""))

        self.xml_attr = {'http': str(not self.http_error), 'https': str(not self.https_error)}
        self.xml_http_vs_https = Element('http_vs_https', attrib = self.xml_attr)
        self.xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        self.xml_result.append(self.xml_http_vs_https)
        
        return PluginBase.PluginResult(self.txt_result, self.xml_result)

