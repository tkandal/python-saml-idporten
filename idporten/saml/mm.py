#! /usr/bin/env python
import sys
from ArtifactResolve import ArtifactResolve

def main(*args):
    artifact_resolve = ArtifactResolve('adalsjljdaljdaljsdsja',
        issuer='dille.ntnu.no') 
    print artifact_resolve.dump(pretty_print=True)

if __name__ == '__main__':
    main(sys.argv[1:])

