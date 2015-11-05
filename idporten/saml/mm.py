#! /usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import re
from ArtifactResolve import ArtifactResolve
from SOAPEnvelope import SOAPEnvelope


XML_DECL_RE = '^<\?xml\ +version=.+encoding=.+\?>'

# Formatted XML match.
XML_DECL_NL = re.compile(XML_DECL_RE + '$',re.IGNORECASE|re.MULTILINE)
# Unformatted XML match.
XML_DECL_NONL = re.compile(XML_DECL_RE, re.IGNORECASE|re.MULTILINE)


def main(*args):
    artifact_resolve = ArtifactResolve('adalsjljdaljdaljsdsja',
        issuer='dille.ntnu.no') 
    signed_artifact = artifact_resolve.sign_document(
        '/var/www/idpp/pki/idppdev.it.ntnu.no.key',
        '/var/www/idpp/pki/terena_ssl_ca_3.pem')

    # Get rid of the XML-declaration.
    if XML_DECL_NL.match(signed_artifact):
        signed_artifact = re.sub(XML_DECL_NL, '', signed_artifact)
    if XML_DECL_NONL.match(signed_artifact):
        signed_artifact = re.sub(XML_DECL_NONL, '', signed_artifact)

    soap_envelope = SOAPEnvelope()
    soap_message = (unicode(soap_envelope) % signed_artifact)
    print soap_message


if __name__ == '__main__':
    main(sys.argv[1:])

