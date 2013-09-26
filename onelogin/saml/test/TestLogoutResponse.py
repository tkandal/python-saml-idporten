from datetime import datetime

from lxml import etree

from nose.tools import eq_ as eq
from xml.dom import minidom

from onelogin.saml.test.util import assert_raises
from onelogin.saml import LogoutResponse


test_raw_response = "nVI9b4MwEN3zK5B3wJiPwClEqpolUro0UYZuhzlaJGIjzkT9+SWoVZMMGWIv5/t47+6dV4ynroed/bSjeyfurWHyvO9TZxjmWCnGwYBFbhkMnojBadi/vO1ABRL6wTqrbScW200puEoTrCVJiapKqkyRIo15LgtdNbHGqmm0qpakhXekgVtrSjGhCG/LPNLWsEPjJpeMYl8WvsoO0RLSJcTJh/A2xK416OaqL+d6CEMZzBeK6YTdzRATqPmzD7YUUsWImDaUYpRomeZxFstcUprVEUrZiPVidRkY5l6GKwkeK4DMNFyaEuu27u3gyPhnGlRQt00bGOuf1Sq8Av6l6WHv0I38hNR3CK+2fm5jR+xGepzMMwPsR62J+cIc3lPf+/7ft59q/QM="


expected_decoded_response = """<samlp:LogoutResponse  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
ID="sb54ad0e00a2b4b62e2eca8809cbf3cabffc2b7ec" Version="2.0" IssueInstant="2013-09-26T17:57:34Z" Destination="http://0.0.0.0:9999/logoutResponse" InResponseTo="023aaa5fe5a14c058363080e56d1a00f">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">idporten-ver2.difi.no-v2</saml:Issuer>
<samlp:Status xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<samlp:StatusCode  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
Value="urn:oasis:names:tc:SAML:2.0:status:Success">
</samlp:StatusCode>
</samlp:Status>
</samlp:LogoutResponse>"""


class TestLogoutResponse(object):
    def test_parse_and_extract_values(self):
        res = LogoutResponse(test_raw_response)

        # Parse the document into a string with same xml tool to get comparable results
        parsed_document = minidom.parseString(etree.tostring(res.document))
        parsed_expected = minidom.parseString(expected_decoded_response)

        eq(parsed_document.toprettyxml(), parsed_expected.toprettyxml())
        eq(res.is_success(), True)
