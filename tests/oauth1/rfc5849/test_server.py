# -*- coding: utf-8 -*-
from __future__ import absolute_import
import time
from oauthlib.oauth1.rfc5849 import *
from ...unittest import TestCase


class ServerTests(TestCase):

    CLIENT_KEY = u'dpf43f3p2l4k3l03'
    CLIENT_SECRET = u'kd94hf93k423kf44'

    RESOURCE_OWNER_KEY = u'kkk9d7dh3k39sjv7'
    RESOURCE_OWNER_SECRET = u'just-a-string    asdasd'

    RSA_KEY = u"-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDk1/bxyS8Q8jiheHeYYp/4rEKJopeQRRKKpZI4s5i+UPwVpupG\nAlwXWfzXwSMaKPAoKJNdu7tqKRniqst5uoHXw98gj0x7zamu0Ck1LtQ4c7pFMVah\n5IYGhBi2E9ycNS329W27nJPWNCbESTu7snVlG8V8mfvGGg3xNjTMO7IdrwIDAQAB\nAoGBAOQ2KuH8S5+OrsL4K+wfjoCi6MfxCUyqVU9GxocdM1m30WyWRFMEz2nKJ8fR\np3vTD4w8yplTOhcoXdQZl0kRoaDzrcYkm2VvJtQRrX7dKFT8dR8D/Tr7dNQLOXfC\nDY6xveQczE7qt7Vk7lp4FqmxBsaaEuokt78pOOjywZoInjZhAkEA9wz3zoZNT0/i\nrf6qv2qTIeieUB035N3dyw6f1BGSWYaXSuerDCD/J1qZbAPKKhyHZbVawFt3UMhe\n542UftBaxQJBAO0iJy1I8GQjGnS7B3yvyH3CcLYGy296+XO/2xKp/d/ty1OIeovx\nC60pLNwuFNF3z9d2GVQAdoQ89hUkOtjZLeMCQQD0JO6oPHUeUjYT+T7ImAv7UKVT\nSuy30sKjLzqoGw1kR+wv7C5PeDRvscs4wa4CW9s6mjSrMDkDrmCLuJDtmf55AkEA\nkmaMg2PNrjUR51F0zOEFycaaqXbGcFwe1/xx9zLmHzMDXd4bsnwt9kk+fe0hQzVS\nJzatanQit3+feev1PN3QewJAWv4RZeavEUhKv+kLe95Yd0su7lTLVduVgh4v5yLT\nGa6FHdjGPcfajt+nrpB1n8UQBEH9ZxniokR/IPvdMlxqXA==\n-----END RSA PRIVATE KEY-----"
  
    class TestServer(Server):

        @property
        def client_key_length(self):
            return 16, 16

        @property
        def resource_owner_key_length(self):
            return 16, 16

        @property
        def enforce_ssl(self):
            return False

        def get_client_secret(self, client_key):
            return ServerTests.CLIENT_SECRET

        def get_resource_owner_secret(self, resource_owner_key):
            return ServerTests.RESOURCE_OWNER_SECRET

        def get_rsa_key(self, client_key):
            return ServerTests.RSA_KEY

        def validate_client_key(self, client_key):
            return ServerTests.CLIENT_KEY == client_key

        def validate_resource_owner_key(self, client_key, resource_owner_key):
            return (ServerTests.CLIENT_KEY == client_key and
                    ServerTests.RESOURCE_OWNER_KEY == resource_owner_key)

        def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
            resource_owner_key=None):
            return True

        def validate_realm(self, client_key, resource_owner_key, realm, uri):
            return True

        def validate_verifier(self, client_key, resource_owner_key, verifier):
            return True

    def test_basic_server_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
        )

        d = Client(self.CLIENT_KEY,
            signature_method=SIGNATURE_RSA,
            rsa_key=self.RSA_KEY,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
        )
        
        s = self.TestServer()

        uri, headers, body = c.sign(u'http://server.example.com:80/init')
        self.assertTrue(s.verify_request(uri, body=body, headers=headers))

        uri, headers, body = d.sign(u'http://server.example.com:80/init')
        self.assertTrue(s.verify_request(uri, body=body, headers=headers))

    def test_server_callback_request(self):
        c = Client(self.CLIENT_KEY,
            client_secret=self.CLIENT_SECRET,
            resource_owner_key=self.RESOURCE_OWNER_KEY,
            resource_owner_secret=self.RESOURCE_OWNER_SECRET,
            callback_uri=u'http://client.example.com/callback'
        )

        uri, headers, body = c.sign(u'http://server.example.com:80/init')

        s = self.TestServer()
        self.assertTrue(s.verify_request(uri, body=body, headers=headers))

    def test_enforce_ssl(self):
        """Ensure SSL is enforced by default."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'http://example.com')

    def test_multiple_source_params(self):
        """Check for duplicate params"""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/?oauth_signature_method=HMAC-SHA1',
            body=u'oauth_version=foo')
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/?oauth_signature_method=HMAC-SHA1',
            headers={u'Authorization' : u'OAuth oauth_signature="foo"'})
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/?oauth_signature_method=HMAC-SHA1',
            body=u'oauth_version=foo',
            headers={u'Authorization' : u'OAuth oauth_signature="foo"'})
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
            body=u'oauth_signature=foo',
            headers={u'Authorization' : u'OAuth oauth_signature_method="foo"'})

    def test_duplicate_params(self):
        """Ensure params are only supplied once"""

        s = Server()
        self.assertRaises(ValueError, s.verify_request, 
            u'https://a.b/?oauth_version=a&oauth_version=b')
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
            body=u'oauth_version=a&oauth_version=b')
        
        # TODO: dict() in parse keqv list auto removes duplicates, wrong? 
        #self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
        #    headers= { u'Authorization' : u'OAuth oauth_version="a",oauth_version="b"' })

    def test_mandated_params(self):
        """Ensure all mandatory params are present."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce'))
          
    def test_oauth_version(self):
        """OAuth version must be 1.0 if present."""
        s = Server()
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_timestamp=1234567890&oauth_signature_method=RSA-SHA1&'
                   u'oauth_version=2.0')) 

    def test_oauth_timestamp(self):
        """Check for a valid UNIX timestamp."""
        s = Server()
        # Invalid timestamp length, must be 10
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   u'oauth_timestamp=123456789')) 
        # Invalid timestamp age, must be younger than 10 minutes
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   u'oauth_timestamp=1234567890')) 
        # Timestamp must be an integer
        self.assertRaises(ValueError, s.verify_request, u'https://a.b/',
             body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
                   u'oauth_version=1.0&oauth_signature_method=RSA-SHA1&'
                   u'oauth_timestamp=123456789a')) 

    def test_signature_method_validation(self):
        """Ensure valid signature method is used."""

        body=(u'oauth_signature=a&oauth_consumer_key=b&oauth_nonce=c&'
              u'oauth_version=1.0&oauth_signature_method=%s&'
              u'oauth_timestamp=1234567890')
    
        uri = u'https://example.com/'

        class HMACServer(Server):
            
            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_HMAC,)

        s = HMACServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'RSA-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'PLAINTEXT') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'shibboleth') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'') 

        class RSAServer(Server):
            
            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_RSA,)

        s = RSAServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'HMAC-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'PLAINTEXT') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'shibboleth') 

        class PlainServer(Server):
            
            @property
            def allowed_signature_methods(self):
                return (SIGNATURE_PLAINTEXT,)

        s = PlainServer()
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'HMAC-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'RSA-SHA1') 
        self.assertRaises(ValueError, s.verify_request, uri, body=body % u'shibboleth') 

    def test_check_methods(self):
        """Ensure values are correctly formatted.
        
        Default setting is to only allow alphanumeric characters and a length
        between 20 and 30 characters.
        """
        #TODO: injection attacks, file traversal
        ts = int(time.time())

        client=(u'oauth_signature=a&oauth_timestamp=%s&oauth_nonce=c&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=%s')
    
        owner=(u'oauth_signature=a&oauth_timestamp=%s&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              u'oauth_token=%s')

        nonce=(u'oauth_signature=a&oauth_timestamp=%s&oauth_nonce=%s&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvwxyz')

        realm=(u'oauth_signature=a&oauth_timestamp=%s&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              u'realm=%s')

        verifier=(u'oauth_signature=a&oauth_timestamp=%s&'
              u'oauth_nonce=abcdefghijklmnopqrstuvwxyz&'
              u'oauth_version=1.0&oauth_signature_method=HMAC-SHA1&'
              u'oauth_consumer_key=abcdefghijklmnopqrstuvxyz&'
              u'oauth_verifier=%s')

        uri = u'https://example.com/'
        s = Server()

        # Invalid characters
        invalid = (ts, u'åbcdefghijklmnopqrstuvwxyz')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % invalid)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % invalid)
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % invalid)
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % invalid)

        # Too short
        short = (ts, u'abcdefghi')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % short)
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % short)
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % short)
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % short)

        # Too long
        loong = (ts, u'abcdefghijklmnopqrstuvwxyz123456789')
        self.assertRaises(ValueError, s.verify_request, uri, body=client % loong) 
        self.assertRaises(ValueError, s.verify_request, uri, body=owner % loong) 
        self.assertRaises(ValueError, s.verify_request, uri, body=nonce % loong) 
        self.assertRaises(ValueError, s.verify_request, uri, body=verifier % loong) 

        # By default no realms are allowed
        test = (ts, u'shibboleth')
        self.assertRaises(ValueError, s.verify_request, uri, body=realm % test)


    def test_timing_attack(self):
        """Ensure near constant time verification."""
        #TODO:
        pass
