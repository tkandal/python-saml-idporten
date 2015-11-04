import subprocess
import platform
import tempfile
import logging

from lxml import etree


class SignableMessageError(Exception):
    """There was a problem signing this message"""
    def __init__(self, msg):
        self._msg = msg
   
    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)


class SignableMessage(object):
    def __init__(self):
        super(SignableMessage, self).__init__()
        self.document = None
        self.node_ns = None


    @staticmethod
    def _get_xmlsec_bin():
        """Get the right xmlsec-command depending on OS."""
        xmlsec_bin = 'xmlsec1'
        if platform.system() == 'Windows':
            xmlsec_bin = 'xmlsec.exe'
        return xmlsec_bin


    def tostring(self, xml_declaration=True, encoding='UTF-8',
        pretty_print=False):
        """Return the XML-document as a string."""
        return etree.tostring(self.document, xml_declaration=xml_declaration,
            encoding=encoding, pretty_print=pretty_print)


    def write_xml_to_file(self, xml_fp):
        """Write the XML-document to a given file."""
        doc_str = self.tostring(pretty_print=True)
        xml_fp.write(doc_str)
        xml_fp.flush()
        print "XML:"
        print doc_str
        xml_fp.seek(0)
        

    def sign_message(self, priv_key_file, ca_cert_file, _node_ns=None,
        _etree=None, _tempfile=None, _subprocess=None):
        """Sign the XML-document and return the signed document
        as a string."""
        if _etree is None:
            _etree = etree
        if _tempfile is None:
            _tempfile = tempfile
        if _subprocess is None:
            _subprocess = subprocess
        if _node_ns is None:
            _node_ns = self.node_ns

        signed_message = None
        with _tempfile.NamedTemporaryFile(suffix='.xml',
            delete=False) as xml_fp:
            self.write_xml_to_file(xml_fp)       

            xmlsec_bin = self._get_xmlsec_bin()
            cmds = [xmlsec_bin,
                '--sign',
                '--privkey-pem',
                priv_key_file + ',' + ca_cert_file,
                '--id-attr:ID',
                _node_ns,
                xml_fp.name]
            
            print "COMMANDS", cmds
            proc = subprocess.Popen(
                cmds,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                )

            signed_message, err = proc.communicate()
            if err:
                raise SignableMessageError(err)

        return signed_message

