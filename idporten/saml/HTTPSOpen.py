# -*- coding: utf-8 -*-
#
# Copright(c) 2015 Norwegian University of Science and Technology
#
"""
A class that communicates over HTTPS-connection.
"""

import httplib
import urlparse


class HTTPSOpen(object):
    "A class that communicates over HTTPS-connection."

    def __init__(self, location_url, send_data, _method='POST', _timeout=30,
        _debug=False):
        """  """
        super(HTTPSOpen, self).__init__()
        parsed_location = urlparse.urlparse(location_url)

        self.location_address = parsed_location.netloc
        self.location_path = parsed_location.path
        self.location_host = self.location_address.split(':')[0]
        self.send_data = send_data
        self.method = _method
        self.timeout = _timeout
        self.debug_conn = _debug


    def communicate(self):
        """Connect to the url, send request and get response."""
        if self.debug_conn:
            print 'Connection parameters:'
            print ('location_address = %s, location_path = %s, send_data = %s,'
                ' location_host = %s, method = %s' % (self.location_address,
                self.location_path, self.send_data, self.location_host,
                self.method))

        conn = httplib.HTTPSConnection(self.location_address,
                timeout=self.timeout)

        conn.request(self.method, self.location_path, body=self.send_data,
            headers={
                "Host": self.location_host,
                "Content-Type": "text/xml; charset=UTF-8",
                "Content-Length": len(self.send_data)
                }
            )
        conn_resp = None
        http_response = conn.getresponse()
        if http_response.status != httplib.OK:
            print ('HTTPS-connectiom failed; status = %d, reason = %s' %
                    (http_response.status, http_response.reason))
        else:
            conn_resp = http_response.read()
        conn.close()
        if self.debug_conn:
            print 'Response:'
            print conn_resp
        return conn_resp
