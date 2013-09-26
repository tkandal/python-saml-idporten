import os
import ConfigParser

from flask import Flask, render_template, request, redirect

from onelogin.saml import AuthRequest, LogoutRequest, Response

app = Flask(__name__)

def read_config(config_file, config_path="."):
    config = ConfigParser.RawConfigParser()
    config_path = os.path.expanduser(config_file)
    config_path = os.path.abspath(config_path)
    with open(config_path) as f:
        config.readfp(f)
    return config

app.cfg = read_config("example.cfg")

settings = {
    'assertion_consumer_service_url'    : app.cfg.get('saml', 'assertion_consumer_service_url'),
    'issuer'                            : app.cfg.get('saml', 'issuer'),
    'name_identifier_format'            : app.cfg.get('saml', 'name_identifier_format'),
    'idp_sso_target_url'                : app.cfg.get('saml', 'idp_sso_target_url'),
    'idp_cert_file'                     : app.cfg.get('saml', 'idp_cert_file'),
    'idp_cert_fingerprint'              : app.cfg.get('saml', 'idp_cert_fingerprint'),
    'sp_name_qualifier'                 : app.cfg.get('saml', 'sp_name_qualifier'),
    'destination'                       : app.cfg.get('saml', 'destination'),
    'private_key_file'                  : app.cfg.get('saml', 'private_key_file'),
    'destination'                       : app.cfg.get('saml', 'destination'),
    'logout_target_url'                 : app.cfg.get('saml', 'logout_target_url'),
    }


user_info = {}


### Routes ###
@app.route('/')
def home():
    """Render home page."""
    url = AuthRequest.create(**settings)
    print "OUTGOING URL:", url
    return redirect(url)


@app.route('/logged_in', methods=['POST', "GET"])
def logged_in():
    print "USER LOGGED IN VIA IDPORTEN"
    print request.values
    SAMLResponse = request.values['SAMLResponse']

    res = Response(
        SAMLResponse,
        settings['idp_cert_fingerprint']
        )
    valid = res.is_valid(settings["idp_cert_file"], settings["private_key_file"])

    uid = res.get_decrypted_assertion_attribute_value("uid")
    name_id = res.name_id
    print "UID", uid
    print "NAME ID: ", name_id
    print "Session index: ", res.get_session_index()
    user_info["uid"] = uid
    user_info["name_id"] = name_id
    user_info["session_index"] = res.get_session_index()

    return render_template('home.html', decrypted = res.decrypted, uid = uid)

@app.route('/log_me_out')
def logout():
    print "Logout requested"
    logout_request = LogoutRequest(name_id=user_info["name_id"],
                                   session_index=user_info["session_index"],
                                   **settings)
    print "Logout xml", logout_request.raw_xml
    url = logout_request.sign(settings["private_key_file"])
    print "OUTGOING LOGOUT URL: ", url
    return redirect(url)

@app.route('/logoutResponse')
def handle_logout_response():
    SAMLResponse = request.values['SAMLResponse']
    print "SAMLResponse", SAMLResponse

    import base64
    decoded_response = base64.b64decode(SAMLResponse)

    import zlib
    values = zlib.decompress(decoded_response, -15)
    print "VALUES", values

    from lxml import etree
    document = etree.fromstring(values)

    user_info = None

    return render_template('home.html')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9999))
    app.run(host='0.0.0.0', port=port, debug=True)
