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

        print "Trying to connect using HTTP..."
        self.http_connection = httplib.HTTPConnection(host, 80)
        try:
            self.http_connection.connect()
            self.http_connection.request("HEAD", "/", headers={"Connection": "close"})
            self.http_response = self.http_connection.getresponse()
            self.http_headers = self.http_response.getheaders()
        except httplib.HTTPException as self.http_error:
            pass
            # print "HTTPS Error: %s" % self.http_error

        finally:
            self.http_connection.close()

        print "Trying to connect using HTTPS..."
        self.https_connection = httplib.HTTPSConnection(host, 443)
        try:
            self.https_connection.connect()
            self.https_connection.request("HEAD", "/", headers={"Connection": "close"})
            self.https_response = self.https_connection.getresponse()
            self.https_headers = self.https_response.getheaders()
        except ssl.SSLError as self.https_error:
            pass
            # print "HTTPS Error: %s" % self.https_error

        finally:
            self.https_connection.close()

        # Save the generated rule to the local rules dir.
        if not self.http_error:
            print "http ok"
            print self.http_headers
        else:
            print "http failed"
            
        if not self.https_error:
            print "https ok"
            print self.https_headers
        else:
            print "https failed."
            
        
        return PluginBase.PluginResult([], [])

