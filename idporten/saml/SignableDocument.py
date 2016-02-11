# -*- coding: utf-8 -*-
# vim: et:ts=4:sw=4:sts=4
#
# Copyright(c) 2016 Norwegian Univeristy of Science and Technology.
#
"""
A base class for signing XML-documents.  Other classes that create
XML-documents should sub-class this class if they need to be signed.
"""
import subprocess
import platform
import tempfile

from lxml import etree


class SignableDocumentError(Exception):
    """There was a problem signing this message"""

    def __init__(self, msg):
        """Inherits Exception super-class."""
        super(SignableDocumentError, self).__init__(msg)
        self._msg = msg


    def __str__(self):
        """String representation of this exception."""
        return '%s: %s' % (self.__doc__, self._msg)


class SignableDocument(object):
    """A base class for signing XML-documents.  The purpose of this
    class is to act as a super-class for classes that need xml-signature(s)."""

    def __init__(self, _node_name=None, _etree=None, _debug=False):
        """More or less an empty constructor.

        Keywords arguments:
        _node_name -- Element to start the signing (default None).
        _etree -- Override the default etree-object (default None).
        _debug -- Print debug-messages (default False).
        """
        super(SignableDocument, self).__init__()
        self.document = None
        self.node_name = _node_name
        self.debug = _debug
        if _etree is None:
            self._etree = etree


    def __str__(self):
        """String-representation of this document."""
        return self._etree.tostring(self.document, xml_declaration=True,
            pretty_print=True)


    def __unicode__(self):
        """Unicode-string of this document."""
        return self._etree.tostring(self.document, xml_declaration=True,
            encoding='UTF-8', pretty_print=True)


    @staticmethod
    def _get_xmlsec_bin():
        """Get the right xmlsec-command depending on OS."""
        xmlsec_bin = 'xmlsec1'
        if platform.system() == 'Windows':
            xmlsec_bin = 'xmlsec.exe'
        return xmlsec_bin


    def tostring(self, xml_declaration=True, encoding='UTF-8',
        pretty_print=False):
        """Return the XML-document as a string.

        Keywords arguments:
        xml_declaration -- Include xml-declartion as first line (default True).
        encoding -- Charset to use for teh returned string (default UTF-8),
        pretty_print -- Include linebreaks and intendation (default False).
        """
        return self._etree.tostring(self.document,
            xml_declaration=xml_declaration, encoding=encoding,
            pretty_print=pretty_print)


    def write_xml_to_file(self, xml_fp):
        """Write the XML-document to a given file.

        Keywords arguments:
        xml_fp -- An open filehandle.
        """
        doc_str = self.tostring(pretty_print=True)
        xml_fp.write(doc_str)
        xml_fp.flush()
        if self.debug:
            print "XML:"
            print doc_str
        xml_fp.seek(0)
        

    def sign_document(self, priv_key_file, _node_name=None,
        _tempfile=None, _subprocess=None):
        """Sign the XML-document and return the signed document
        as a string.

        Keyword arguments:
        priv_key_file -- File containing the private key to use for signing.
        ca_cert_file -- File containing the CA-certificate.
        _node_name -- The XML-node where the signing should start.
        _tempfile -- Override the default tempfile-object (default None).
        _subprocess -- Overrride the default subprocess-object (default None).

        Raises SignableDocumentError if an error occurs."""
        if _tempfile is None:
            _tempfile = tempfile
        if _subprocess is None:
            _subprocess = subprocess
        if _node_name is None:
            _node_name = self.node_name

        signed_message = None
        with _tempfile.NamedTemporaryFile(suffix='.xml',
            delete=False) as xml_fp:
            self.write_xml_to_file(xml_fp)       

            xmlsec_bin = self._get_xmlsec_bin()
            cmds = [xmlsec_bin,
                '--sign',
                '--privkey-pem',
                priv_key_file,
                '--id-attr:ID']

            if _node_name:
                cmds.append(_node_name)

            cmds.append(xml_fp.name)

            if self.debug:
                print "COMMANDS", cmds
            proc = subprocess.Popen(
                cmds,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                )

            signed_message, err = proc.communicate()
            if err:
                raise SignableDocumentError(err)

        return signed_message

