# -*- coding: utf-8 -*-
"""
Creates an SAML2 ArtifactResponse message.
"""
import base64

from lxml import etree
from datetime import datetime, timedelta

from SignatureVerifier import SignatureVerifier

from Response import ResponseValidationError, ResponseNameIDError
from Response import ResponseConditionError


namespaces = {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'soap-env': 'http://schemas.xmlsoap.org/soap/envelope/'}

class ArtifactResponse(object):
    """Creates an SAML2 ArtifactResponse message."""

    def __init__(self, art_resp, _base64=None, _etree=None):
        super(ArtifactResponse, self).__init__()
        if _base64 is None:
            _base64 = base64
        if _etree is None:
            _etree = etree
        
        self._signature = None
        self._document = _etree.fromstring(art_resp)


    def _parse_datetime(self, dt):
        return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%SZ')


    def is_valid(self, idp_cert_filename, private_key_file,
        _clock=None, _verifier=None
        ):
        """
        Verify that the samlp:Response is valid.
        Return True if valid, otherwise False.
        """
        if _clock is None:
            _clock = datetime.utcnow
        if _verifier is None:
            _verifier = SignatureVerifier(idp_cert_filename, private_key_file)

        conditions = self._document.xpath(
            '/soap-env:Envelope/soap-env:Body/samlp:ArtifactResponse/samlp:Response/saml:Assertion/saml:Conditions',
            namespaces=namespaces,
            )
       
        now = _clock()

        not_before = None
        not_on_or_after = None
        for condition in conditions:
            not_on_or_after = condition.attrib.get('NotOnOrAfter', None)
            not_before = condition.attrib.get('NotBefore', None)

        if not_before is None:
            #notbefore condition is not mandatory. If it is not specified, use yesterday as not_before condition
            not_before = (now-timedelta(1,0,0)).strftime('%Y-%m-%dT%H:%M:%SZ')
        #TODO: this is in the encrypted part in our case..
        #if not_on_or_after is None:
        #    raise ResponseConditionError('Did not find NotOnOrAfter condition')

        not_before = self._parse_datetime(not_before)
        #not_on_or_after = self._parse_datetime(not_on_or_after)

        if now < not_before:
            raise ResponseValidationError(
                'Current time is earlier than NotBefore condition'
                )
        #if now >= not_on_or_after:
        #    raise ResponseValidationError(
        #        'Current time is on or after NotOnOrAfter condition'
        #        )

        is_valid, decrypted = _verifier.verify_and_decrypt(self._document, self._signature, _node_ns='urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse')

        self.decrypted = decrypted
        self._decrypted_document = etree.fromstring(self.decrypted)
        return is_valid


    def get_assertion_attribute_value(self, attribute_name):
        """
        Get the value of an AssertionAttribute, located in an Assertion/AttributeStatement/Attribute[@Name=attribute_name/AttributeValue tag
        """
        result = self._document.xpath('/soap-env:Envelope/soap-env:Body/samlp:ArtifactResponse/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue'%attribute_name,namespaces=namespaces)
        return [n.text.strip() for n in result]


    def get_decrypted_assertion_attribute_value(self, attribute_name):
        """
        Get the value of an AssertionAttribute, located in an Assertion/AttributeStatement/Attribute[@Name=attribute_name/AttributeValue tag
        """
        result = self._decrypted_document.xpath('/soap-env:Envelope/soap-env:Body/samlp:ArtifactResponse/samlp:Response/saml:EncryptedAssertion/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue' % attribute_name, namespaces=namespaces)
        return [n.text.strip() for n in result]


    def get_session_index(self):
        result = self._decrypted_document.xpath(
            '/soap-env:Envelope/soap-env:Body/samlp:ArtifactResponse/samlp:Response/saml:EncryptedAssertion/saml:Assertion/saml:AuthnStatement/@SessionIndex',
            namespaces=namespaces,
            )
        
        return result[0]


    def _get_name_id(self):
        result = self._decrypted_document.xpath(
            '/soap-env:Envelope/soap-env:Body/samlp:ArtifactResponse/samlp:Response/saml:EncryptedAssertion/saml:Assertion/saml:Subject/saml:NameID',
            namespaces=namespaces,
            )
        length = len(result)
        if length > 1:
            raise ResponseNameIDError(
                'Found more than one name ID'
                )
        if length == 0:
            raise ResponseNameIDError(
                'Did not find a name ID'
                )

        node = result.pop()

        return node.text.strip()

    name_id = property(
        fget=_get_name_id,
        doc="The value requested in the name_identifier_format, e.g., the user's email address",
        )

