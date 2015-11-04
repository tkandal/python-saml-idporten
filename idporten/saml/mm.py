#! /usr/bin/env python
import sys
from ArtifactResolve import ArtifactResolve
from SOAPEnvelope import SOAPEnvelope

def main(*args):
    artifact_resolve = ArtifactResolve('adalsjljdaljdaljsdsja',
        issuer='dille.ntnu.no') 
    signed_artifact = artifact_resolve.sign_document(
        '/var/www/idpp/pki/idppdev.it.ntnu.no.key',
        '/var/www/idpp/pki/terena_ssl_ca_3.pem')
    soap_envelope = SOAPEnvelope()
    print soap_envelope.tostring(signed_artifact)


if __name__ == '__main__':
    main(sys.argv[1:])

