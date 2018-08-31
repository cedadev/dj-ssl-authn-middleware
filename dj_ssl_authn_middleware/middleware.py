__author__ = "William Tucker"
__copyright__ = "Copyright (c) 2014, Science & Technology Facilities Council (STFC)"
__license__ = "BSD - see LICENSE file in top-level directory"

import re
import httplib
import logging

from datetime import datetime
from OpenSSL import crypto

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class ApacheSSLAuthnMiddleware(MiddlewareMixin):
    """Perform SSL peer certificate authentication making use of Apache
    SSL environment settings
    
    B{This class relies on SSL environment settings being present as available
    when run embedded within Apache using for example mod_wsgi}
    
    - SSL Client certificate is expected to be present in environ as 
    SSL_CLIENT_CERT key as set by Apache SSL with ExportCertData option to
    SSLOptions directive enabled.
    """
    
    SSL_VALIDATION_KEYNAME = 'SSL_CLIENT_VERIFY'
    SSL_VALIDATION_SUCCESS_ID = 'SUCCESS'
    
    SSL_CLIENT_CERT_KEYNAME = 'SSL_CLIENT_CERT'
    PEM_CERT_PREFIX = '-----BEGIN CERTIFICATE-----'
    
    # isValidCert requires special parsing of certificate when passed via a 
    # proxy
    X509_CERT_PAT = re.compile('(\s?-----[A-Z]+\sCERTIFICATE-----\s?)|\s+')
    
    # Flag to other middleware that authentication succeeded by setting this key
    # in the environ to True.  This is done in the isValidCert method
    SSL_AUTHN_SUCCESS_ENVIRON_KEYNAME = 'SSL_AUTHN_SUCCESS'
    
    # Django configuration options
    RE_PATH_MATCH_LIST = 'SSL_AUTHN_RE_PATHS'
    
    def __init__(self, *args):
        """Read configuration settings from the global and application specific
        ini file settings
        """
        super(ApacheSSLAuthnMiddleware, self).__init__(*args)
        
        rePathMatchListVal = getattr(settings, self.RE_PATH_MATCH_LIST, [''])
        self.rePathMatchList = [re.compile(r) for r in rePathMatchListVal]
    
    def process_request(self, request):
        """Check for peer certificate in environment and if present carry out
        authentication
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        """
        logger.debug("ApacheSSLAuthnMiddleware.__call__ ...")
        
        if not self._pathMatch():
            logger.debug("ApacheSSLAuthnMiddleware: ignoring path [%s]", 
                      self.pathInfo)
            return self._setResponse(request)
        
        elif not self._isSSLClientCertSet(request):
            logger.error("ApacheSSLAuthnMiddleware: No SSL Client certificate "
                      "for request to [%s]; setting HTTP 401 Unauthorized", 
                      self.pathInfo)
            return self._setErrorResponse(code=401,
                                          msg='No client SSL Certificate set')
        
        # Parse cert from environ keyword
        client_cert = self._parse_cert(request)
        
        if self.is_valid_client_cert(request, client_cert):
            self._setUser()
            return self._setResponse(request)
        else:
            return self._setErrorResponse(code=401)

    def _setResponse(self, request, start_response=None, 
                     notFoundMsg='No application set for '
                                 'ApacheSSLAuthnMiddleware',
                     notFoundMsgContentType=None):
        """Convenience method to wrap call to next WSGI app in stack or set an
        error if none is set
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary defaults to 
        environ object attribute.  For the latter to be available, the initCall
        decorator method must have been invoked.
        @type start_response: function
        @param start_response: standard WSGI start response function defaults 
        to start_response object attribute.  For the latter to be available, 
        the initCall decorator method must have been invoked.
        """
        environ = request.environ
        
        if start_response is None:
            start_response = self.start_response

        if self._app:
            return self._app(environ, start_response)
        else:
            return self._setErrorResponse(start_response=start_response, 
                                          msg=notFoundMsg,
                                          code=404,
                                          contentType=notFoundMsgContentType)
    
    def _setErrorResponse(self, start_response=None,
                          msg='Invalid SSL client certificate',
                          code=500, contentType=None):
        '''Convenience method to set a simple error response
        
        @type start_response: function
        @param start_response: standard WSGI callable to set the HTTP header
        defaults to start_response object attribute.  For the latter to be 
        available, the initCall decorator method must have been invoked.   
        @type msg: basestring
        @param msg: optional error message
        @type code: int
        @param code: standard HTTP error response code
        @type contentType: basestring
        @param contentType: set 'Content-type' HTTP header field - defaults to
        'text/plain'
        '''            
        if start_response is None:
            start_response = self.start_response
            
        status = '%d %s' % (code, httplib.responses[code])
        if msg is None:
            response = status
        else:
            response = msg
        
        if contentType is None:
            contentType = 'text/plain'
                
        start_response(status,
                       [('Content-type', contentType),
                        ('Content-Length', str(len(response)))])
        return [response]
    
    def _pathMatch(self, request):
        """Apply a list of regular expression matching patterns to the contents
        of environ['PATH_INFO'], if any match, return True.  This method is
        used to determine whether to apply SSL client authentication
        """
        path = request.environ.get('PATH_INFO')
        for regEx in self.rePathMatchList:
            if regEx.match(path):
                return True
            
        return False
    
    def _isSSLClientCertSet(self, request):
        """Check for SSL Certificate set in environ"""
        sslClientCert = request.environ.get(
                        self.SSL_CLIENT_CERT_KEYNAME, '')
        return sslClientCert.startswith(self.PEM_CERT_PREFIX)
    
    isSSLClientCertSet = property(fget=_isSSLClientCertSet,
                                  doc="Check for client X.509 certificate "
                                      "%r setting in environ" %
                                      SSL_CLIENT_CERT_KEYNAME)
    
    def _parse_cert(self, request):
        '''Parse client certificate from environ'''
        pem_cert = request.environ[self.SSL_CLIENT_CERT_KEYNAME]
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        return cert
    
    @staticmethod
    def _is_cert_expired(cert):
        '''Check if input certificate has expired
        @param cert: X.509 certificate
        @type cert: OpenSSL.crypto.X509
        @return: true if expired, false otherwise
        @rtype: bool
        '''
        notAfter = cert.get_notAfter()
        dtNotAfter = datetime.strptime(notAfter, '%Y%m%d%H%M%S%fZ')
        dtNow = datetime.utcnow()
        
        return dtNotAfter < dtNow
    
    def is_valid_client_cert(self, request, cert):
        '''Check certificate time validity
        
        TODO: allow verification against CA certs - current assumption is 
        that Apache config performs this task!
        '''
        
        validation_result = request.environ.get(
            self.SSL_VALIDATION_KEYNAME
        )
        if not validation_result == self.SSL_VALIDATION_SUCCESS_ID:
            return False
        
        if self.__class__._is_cert_expired(cert):
            return False
        
        # Set environ key to indicate client authentication
        request.environ[self.SSL_AUTHN_SUCCESS_ENVIRON_KEYNAME] = True
        return True
    
    def _setUser(self):
        """Interface hook for a derived class to set user ID from certificate 
        set or other context info.
        """


class DjSSLAuthnMiddleware(ApacheSSLAuthnMiddleware):
    """Middleware for
    """
    
    USERNAME_ENVIRON_KEYNAME = 'REMOTE_USER'
    
    def process_request(self, request):
        '''Check for peer certificate in environment and if present carry out
        authentication. If no certificate is present or it is  present but
        invalid no 401 response is set.
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        
        if not self._pathMatch(request):
            # ignoring path which are not applicable to this middleware
            pass
        
        elif not self._isSSLClientCertSet(request):
            logger.debug("AuthKitSSLAuthnMiddleware: no client certificate set - "
                      "passing request to next middleware in the chain ...")
        
        else:
            client_cert = self._parse_cert(request)
            if self.is_valid_client_cert(request, client_cert):
                # Update session cookie with user ID
                self._setUser(request, client_cert)
                logger.debug("AuthKitSSLAuthnMiddleware: set "
                          "environ['REMOTE_USER'] = {}".format(
                          request.environ.get('REMOTE_USER')))
        
        # Pass request to next middleware in the chain without setting an
        # error response - see method doc string for explanation.
        pass
    
    def _setUser(self, request, cert):
        """Set user ID in AuthKit cookie from client certificate submitted
        """
        subject = cert.get_subject()
        userId = subject.commonName
        
        request.environ[self.USERNAME_ENVIRON_KEYNAME] = userId
