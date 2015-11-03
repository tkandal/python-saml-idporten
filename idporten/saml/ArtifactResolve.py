#import zlib
#import base64
import uuid
#import urllib
#import tempfile
#import subprocess as subp

from datetime import datetime
from lxml import etree
from lxml.builder import ElementMaker

from SignableRequest import SignableRequest


class ArtifactResolve(object):
    def __init__(self, artifact, _clock=None, _uuid=None, **kwargs):

        super(ArtifactResolve, self).__init__()

        if _clock is None:
            _clock = datetime.utcnow
        if _uuid is None:
            _uuid = uuid.uuid4

        issuer = kwargs.pop('issuer')

        now = _clock()
        now = now.replace(microsecond=0)
        now_iso = now.isoformat() + ".875Z"   #TODO: add better format here

        unique_id = _uuid()
        unique_id = unique_id.hex

        samlp_maker = ElementMaker(
            namespace='urn:oasis:names:tc:SAML:2.0:protocol',
            nsmap=dict(saml2p='urn:oasis:names:tc:SAML:2.0:protocol'),
            )
        saml_maker = ElementMaker(
            namespace='urn:oasis:names:tc:SAML:2.0:assertion',
            nsmap=dict(saml2='urn:oasis:names:tc:SAML:2.0:assertion'),
            )
        artifact_resolve = samlp_maker.ArtifactResolve(
            Version='2.0',
            IssueInstant=now_iso,
            ID=unique_id,
            )
        saml_issuer = saml_maker.Issuer()
        saml_issuer.text = issuer
        artifact_resolve.append(saml_issuer)

        saml_artifact = saml_maker.Artifact()
        saml_artifact.text = artifact
        artifact_resolve.append(saml_artifact)

        signature_maker = ElementMaker(
             namespace='http://www.w3.org/2000/09/xmldsig#',
            )

        signature_elem = signature_maker.Signature()

        signature_elem.SignedInfo()

        signature_elem.CanonicalizationMethod(
            Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'
            )

        signature_elem.SignatureMethod(
            Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            )

        reference_maker = signature_elem.Reference(
            ID='#' + unique_id
            )


        transforms_elems = reference_maker.Transforms()
        transforms_elems.Transform(
            Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'
            )
        transform_maker = ElementMaker()
        transform_canon = transform_maker.Transform(
            Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'
            )
        transforms_elems.append(transform_canon)

        reference_maker.DigestMethod(
            Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'
            )
        reference_maker.DigestValue()

        signature_elem.SignatureValue()
        signature_elem.KeyInfo()

        self.document = artifact_resolve
        print etree.tostring(self.document, pretty_print=True, encoding='UTF-8')


'''<?xml version='1.0' encoding='UTF-8'?>
<ns0:ArtifactResolve xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"
ID="%s"
IssueInstant="%s"
Version="2.0">
<ns1:Issuer xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion">%s</ns1:Issuer>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <Reference URI="#%s">
    <Transforms>
      <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </Transforms>
    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
    <DigestValue />
  </Reference>
  </SignedInfo>
  <SignatureValue />
  <KeyInfo />
  </Signature>
<ns0:Artifact>%s</ns0:Artifact>
</ns0:ArtifactResolve>'''

