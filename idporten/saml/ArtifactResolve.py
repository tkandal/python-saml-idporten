"""
Creates an SAML2 ArtifactResolve message.
"""
#
# Copyright(c) 2015 Norwegian Univeristy of Science and Technology.
#
import uuid

from datetime import datetime
from lxml.builder import ElementMaker

from SignableDocument import SignableDocument


class ArtifactResolve(SignableDocument):
    """Creates an SAML2 ArtifactResolve message."""

    def __init__(self, artifact, _clock=None, _uuid=None, **kwargs):
        """This should produce an SAML2 ArtifactResolve like this:

        <samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="%s"
            IssueInstant="%s"
            Version="2.0">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:Issuer>
        <ns1:Signature xmlns:ns1="http://www.w3.org/2000/09/xmldsig#">
            <ns1:SignedInfo>
                <ns1:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ns1:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <ns1:Reference URI="#%s">
                    <ns1:Transforms>
                        <ns1:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ns1:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ns1:Transforms>
                    <ns1:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <ns1:DigestValue />
                </ns1:Reference>
            </ns1:SignedInfo>
            <ns1:SignatureValue />
            <ns1:KeyInfo >
                <ns1:X509Data />
            </ns1:KeyInfo>
        </ns1:Signature>
        <samlp:Artifact>%s</samlp:Artifact>
        </samlp:ArtifactResolve>"""
        super(ArtifactResolve, self).__init__()
        self.node_ns = 'urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResolve'

        if _clock is None:
            _clock = datetime.utcnow
        if _uuid is None:
            _uuid = uuid.uuid4

        now = _clock()
        now = now.replace(microsecond=0)
        now_iso = now.isoformat() + ".875Z"

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

        artifact_resolve.append(self._create_signature(unique_id))

        # Add Issuer and artifact under signature.
        saml_issuer = saml_maker.Issuer()
        saml_issuer.text = kwargs.get('issuer', '')
        artifact_resolve.append(saml_issuer)

        saml_artifact = samlp_maker.Artifact()
        saml_artifact.text = artifact
        artifact_resolve.append(saml_artifact)

        self.document = artifact_resolve


    @staticmethod
    def _create_signature(unique_id):
        """Craates all XML-elements needed for an XML-signature."""
        signature_maker = ElementMaker(
            namespace='http://www.w3.org/2000/09/xmldsig#',
            nsmap=dict(ns1='http://www.w3.org/2000/09/xmldsig#')
            )

        signature_elem = signature_maker.Signature()

 
        signed_info_elem = signature_maker.SignedInfo()
       
        signature_elem.append(signed_info_elem)

        signed_info_elem.append(signature_maker.CanonicalizationMethod(
            Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'
            ))

        signed_info_elem.append(signature_maker.SignatureMethod(
            Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            ))

        reference_elem = signature_maker.Reference(
            URI='#' + unique_id
            )

        signed_info_elem.append(reference_elem)

        transforms_elem = signature_maker.Transforms()
        reference_elem.append(transforms_elem)

        transforms_elem.append(signature_maker.Transform(
            Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'
            ))
        transforms_elem.append(signature_maker.Transform(
            Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'
            ))

        reference_elem.append(signature_maker.DigestMethod(
            Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'
            ))
        reference_elem.append(signature_maker.DigestValue())

        signature_elem.append(signature_maker.SignatureValue())

        key_info_elem = signature_maker.KeyInfo()
        key_info_elem.append(signature_maker.X509Data())

        signature_elem.append(key_info_elem)
        return signature_elem

