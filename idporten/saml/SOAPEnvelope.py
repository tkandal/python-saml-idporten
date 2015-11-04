"""
Creates a SOAP-Envelope.
"""
#
# Copyright(c) 2015 Norwegian Univeristy of Science and Technology.
#
import re

from lxml import etree
from lxml.builder import ElementMaker



XML_DECL = re.compile('^<\?xml\ +version=..+$', re.IGNORECASE|re.MULTILINE)


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
    """Creates a SOAP-envelope with a string-placeholder as body."""
    def __init__(self):
        """Creates a SOAP-envelope."""
        super(SOAPEnvelope, self).__init__()
        soap_envelope_maker = ElementMaker(
            namespace='http://schemas.xmlsoap.org/soap/envelope/',
            nsmap=dict(soapp='http://schemas.xmlsoap.org/soap/envelope/')
            )
        
        soap_envelope = soap_envelope_maker.Envelope()
        soap_body = soap_envelope_maker.Body()
        
        soap_body.text = '\n%s'
        soap_envelope.append(soap_body)
        self.envelope = soap_envelope


    def __str__(self):
        """String-representation of this object."""
        return etree.tostring(self.envelope, xml_delaration=True,
            pretty_print=True)


    def __unicode__(self):
        """Unicode-representation of this object."""
        return etree.tostring(self.envelope, xml_delaration=True,
            encoding='UTF-8', pretty_print=True)


    def tostring(self, body):
        """Insert body as the SOAP-body and return this envelope as
        a string.

        Raise SOAPEnvelopeError if the body-parameter is not a string
        or unicode."""
        if isinstance(body, str) or isinstance(body, unicode):
            # Get rid of the XML-declaration if it exists.
            if XML_DECL.match(body):
                splitted_body = body.split('\n')
                body = '\n'.join(splitted_body[1:])
            return (etree.tostring(self.envelope, xml_declaration=True,
                pretty_print=True, encoding='UTF-8') % body)
        else:
            raise SOAPEnvelopeError('Illegal parameter.  Must be a '
                'string or unicode')

