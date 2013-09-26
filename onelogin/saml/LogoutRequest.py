import zlib
import base64
import uuid
import urllib
import tempfile
import subprocess as subp

from datetime import datetime
from lxml import etree
from lxml.builder import ElementMaker


def sign_request(urlencoded_request, private_key_file):
    with tempfile.NamedTemporaryFile(delete=False) as output_file:
        output_file.write(urlencoded_request.encode("utf-8"))
        output_file.seek(0)

        cmds = [
            "openssl",
            "sha1",
            "-sign",
            private_key_file,
            output_file.name ]

        proc = subp.Popen(
            cmds,
            stdout=subp.PIPE,
            stderr=subp.PIPE)
        out, err = proc.communicate()
        print err

    out = base64.b64encode(out)
    return urllib.urlencode([("Signature", out),])



class LogoutRequest(object):
    def __init__(self,
        _clock=None,
        _uuid=None,
        _zlib=None,
        _base64=None,
        _urllib=None,
        **kwargs):
        """Create a URL string which can be used to redirect a samlp:AuthnRequest to the identity provider.
        Return a URL string containing the idp_sso_target_url and a deflated, base64-encoded, url-encoded (in that order) samlp:AuthnRequest XML element as the value of the SAMLRequest parameter.

        Keyword arguments:
        assertion_consumer_service_url -- The URL at which the SAML assertion should be received.
        issuer -- The name of your application. Some identity providers might need this to establish the identity of the service provider requesting the login.
        name_identifier_format -- The format of the username required by this application. If you need the email address, use "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress". See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf section 8.3 for other options. Note that the identity provider might not support all options.
        idp_sso_target_url -- The URL to which the authentication request should be sent. This would be on the identity
        """
        if _clock is None:
            _clock = datetime.utcnow
        if _uuid is None:
            _uuid = uuid.uuid4

        self.logout_target_url = kwargs.pop('logout_target_url')
        issuer = kwargs.pop('issuer')
        name_id = kwargs.pop('name_id')
        session_index = kwargs.pop('session_index')

        now = _clock()
        # Resolution finer than milliseconds not allowed
        # http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf Section
        # 1.3.3
        now = now.replace(microsecond=0)
        now_iso = now.isoformat() + ".000Z"   #TODO: add better format here

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

        logout_request = samlp_maker.LogoutRequest(
            Version='2.0',
            IssueInstant=now_iso,
            ID=unique_id,
            Destination=self.logout_target_url
        )

        saml_issuer = saml_maker.Issuer()
        saml_issuer.text = issuer
        logout_request.append(saml_issuer)

        saml_name_id = saml_maker.NameID()
        saml_name_id.text = name_id
        logout_request.append(saml_name_id)

        saml_session_index = samlp_maker.SessionIndex()
        saml_session_index.text = session_index
        logout_request.append(saml_session_index)

        self.raw_xml = etree.tostring(logout_request,
                                      xml_declaration=True,
                                      encoding='UTF-8')


    def sign(self, private_key_file):

        compressed_request = zlib.compress(self.raw_xml)
        # Strip the first 2 bytes (header) and the last 4 bytes (checksum) to get the raw deflate
        deflated_request = compressed_request[2:-4]
        encoded_request = base64.b64encode(deflated_request)
        sig_alg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        urlencoded_request = urllib.urlencode(
            [('SAMLRequest', encoded_request),
             ('SigAlg', sig_alg)],)

        signature = sign_request(urlencoded_request, private_key_file)

        return '{url}?{query}&{Signature}'.format(
            url=self.logout_target_url,
            query=urlencoded_request,
            Signature=signature
            )
