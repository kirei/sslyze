#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginOCSP.py
# Purpose:      Plugin that implements OCSP validation of a certificate.
#               The plugin supports both validation using OCSP responder and
#               OCSP stapling.
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

import os
from xml.etree.ElementTree import Element
import httplib
from plugins import PluginBase
from utils.ExternalCommand import ExternalCommand


class PluginOCSP(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginOCSP", description=(''))
    interface.add_command(
        command="stapling",
        help="Checks if the server supports OCSP stapling and reports the "
             "status given by the server.",
        dest=None)

    def process_task(self, target, command, args):

        output_format = '        {0:<25} {1}'

        ocsp_result = None

        # Text output
        cmd_title = 'OCSP validation'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        txt_result.append(output_format.format("Nothing to see here.", ""))

        # XML output
        xml_ocsp_attr = {'status': str(None)}
        xml_ocsp = Element('ocsp', attrib = xml_ocsp_attr)

        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_ocsp)

        return PluginBase.PluginResult(txt_result, xml_result)

