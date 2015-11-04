#! /usr/bin/env python
import sys
from ArtifactResolve import ArtifactResolve

def main(*args):
    artifact_resolve = ArtifactResolve('adalsjljdaljdaljsdsja',
        issuer='dille.ntnu.no') 
    ## print artifact_resolve.tostring(pretty_print=True)
    print artifact_resolve.sign_message(
        '/var/www/idpp/pki/idppdev.it.ntnu.no.key',
        '/var/www/idpp/pki/terena_ssl_ca_3.pem')


if __name__ == '__main__':
    main(sys.argv[1:])

