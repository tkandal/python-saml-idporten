# -*- coding: utf-8 -*-
#
# Copyright(c) 2015 Norwegian Univeristy of Science and Technology.
#
"""
Creates a SOAP-Envelope.
"""

from lxml import etree
from lxml.builder import ElementMaker


class SOAPEnvelopeError(Exception):
    """There was a problem with the SOAP-body."""
   
    def __init__(self, msg):
        """Inherits Exception super-class."""
        super(SOAPEnvelopeError, self).__init__(msg)
        self._msg = msg


    def __str__(self):
        """String representation of this exception."""
        return '%s: %s' % (self.__doc__, self._msg)


class SOAPEnvelope(object):
    """Creates a SOAP-envelope with a string-placeholder as body,
    like this:

    <?xml version='1.0' encoding='UTF-8'?>
    <soapp:Envelope xmlns:soapp="http://schemas.xmlsoap.org/soap/envelope/">
        <soapp:Body>
        %s
        </soapp:Body>
    </soapp:Envelope>
    """
    def __init__(self):
        """Creates a SOAP-envelope."""
        super(SOAPEnvelope, self).__init__()
        soap_envelope_maker = ElementMaker(
            namespace='http://schemas.xmlsoap.org/soap/envelope/',
            nsmap=dict(soapp='http://schemas.xmlsoap.org/soap/envelope/')
            )
        
        soap_envelope = soap_envelope_maker.Envelope()
        soap_body = soap_envelope_maker.Body()
        
        soap_body.text = '%s'
        soap_envelope.append(soap_body)
        self.envelope = soap_envelope


    def __str__(self):
        """String-representation of this object."""
        return etree.tostring(self.envelope, xml_declaration=True,
            pretty_print=True)


    def __unicode__(self):
        """Unicode-representation of this object."""
        return etree.tostring(self.envelope, xml_declaration=True,
            encoding='UTF-8', pretty_print=True)

