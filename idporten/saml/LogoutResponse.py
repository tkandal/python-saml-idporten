# -*- coding: utf-8 -*-
# vim: et:ts=4:sw=4:sts=4
import base64
import zlib
from lxml import etree


namespaces = dict(
    samlp='urn:oasis:names:tc:SAML:2.0:protocol',
    saml='urn:oasis:names:tc:SAML:2.0:assertion',
    )


class LogoutResponse(object):
    def __init__(self, response):
        """
        Extract information from an samlp:LogoutResponse
        Arguments:
        response -- The base64 encoded and compressed XML string containing the samlp:Response
        """

        # Decode and decompress the message
        decoded_response = base64.b64decode(response)

        # -15 to ignore the header
        decompressed_response = zlib.decompress(decoded_response, -15)

        self.document = etree.fromstring(decompressed_response)


    def is_success(self):
        """
        Check if the logout was successful.

        Criterias:
        - The document must have decoded, decompressed and parse correctly.
        - It must have StatusCode == Success.
        """
        result = self.document.xpath(
            '/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value',
            namespaces=namespaces)

        return (len(result) == 1 and
                result[0] == "urn:oasis:names:tc:SAML:2.0:status:Success")

