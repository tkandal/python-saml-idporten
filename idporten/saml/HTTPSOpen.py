# -*- coding: utf-8 -*-
# vim: et:ts=4:sw=4:sts=4
#
# Copyright(c) 2016 Norwegian University of Science and Technology
#
"""
A class that communicates over HTTPS-connection.
"""

import httplib
import urlparse


class HTTPSOpen(object):
    """A class that communicates over HTTPS-connection.  The purpose of
    this class is to post data to a given location (URL).  The default
    behaviour is configured to post a SOAP-Envelope.
    The connection is regarded as failied if the returned HTTP-status
    is different from 200.
    """

    def __init__(self, location_url, send_data, _method='POST', _timeout=30,
        _content_type='text/xml; charset=UTF-8', _debug=False):
        """
        Open a https connection to an URL.  The URL can specify port on
        the format https://hostname:port/...; if no port is specified
        the default https-port will be used.

        Keyword arguments:
        location_url -- The location (URL) to post the data.
        send_data -- The data to post, and the data need to be
                     urlencoded if it is required and the _content_type-
                     parameter must be set accordingly.
        _method -- Default post.
        _timeout -- The connect-timeout (default 30 secs).
        _content_type -- The content-type of the data
                         (default text/xml; charset UTF-8).
        _debug -- Print debug (default False).
        """
        super(HTTPSOpen, self).__init__()
        parsed_location = urlparse.urlparse(location_url)

        host_and_port = parsed_location.netloc.split(':')
        self.location_host = None
        self.location_port = None
        if len(host_and_port) == 2:
            self.location_host = host_and_port[0]
            self.location_port = int(host_and_port[1])
        else:
            self.location_host = host_and_port[0]
            self.location_port = httplib.HTTPS_PORT
        self.location_path = parsed_location.path
        if self.location_path is None or len(self.location_path) == 0:
            self.location_path = '/'
        self.method = _method
        self.content_type = _content_type
        self.send_data = send_data
        self.timeout = _timeout
        self.debug_conn = _debug


    def communicate(self):
        """
        Connect to the URL, send request and return the raw response.
        If the returned HTTP-status from the server is not equal to 200,
        the connection is regarded as failed and this method will return None.
        """
        if self.debug_conn:
            print 'Connection parameters:'
            print ('location_host = %s, location_port = %d, '
                   'location_path = %s, method = %s, content_type = %s, '
                   'timeout = %d, send_data:\n%s' %
                (self.location_host, self.location_port, self.location_path,
                self.method, self.content_type, self.timeout, self.send_data))

        conn = httplib.HTTPSConnection(self.location_host,
                                       port=self.location_port,
                                       timeout=self.timeout)

        headers = {
            "Host": self.location_host,
            "Content-Type": self.content_type,
            "Content-Length": len(self.send_data),
            }
        if self.debug_conn:
            print ('Headers:\n%s' % str(headers))
        conn.request(self.method, self.location_path, body=self.send_data,
                     headers=headers)

        conn_resp = None
        http_response = conn.getresponse()
        if http_response.status >= httplib.MULTIPLE_CHOICES:
            print ('HTTPS-connection failed; status = %d, reason = %s' %
                    (http_response.status, http_response.reason))
        elif http_response.status > httplib.OK:
            print ('Unexpected status; status = %d, reason = %s' %
                    (http_response.status, http_response.reason))
        elif http_response.status == httplib.OK:
            conn_resp = http_response.read()
        conn.close()
        if self.debug_conn:
            print 'Response:'
            print conn_resp
        return conn_resp

