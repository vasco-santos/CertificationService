import Pyro4

from M2Crypto import X509, RSA, EVP, BIO, ASN1
from Crypto.Hash import SHA


class CertificationSubject(object):

    def __init__(self, cert, priv_key, ca_cert, passphrase):

        def getPassphrase(*args):
            return str(passphrase.encode('utf-8'))

        self.cert = X509.load_cert(cert.encode('utf-8'))
        self.ca_cert = X509.load_cert_string(ca_cert.decode('hex'))
        self.priv_key = RSA.load_key(priv_key.encode('utf-8'), getPassphrase)
        # Private key for signing
        self.signEVP = EVP.PKey()
        self.signEVP.assign_rsa(self.priv_key)

    def validCertificationAuthorityCertificate(self):
        return self.ca_cert.check_ca() and self.ca_cert.verify(self.ca_cert.get_pubkey())

    def validCertificate(self):
        return self.cert.verify(self.ca_cert.get_pubkey())

    def signData(self, data):
        self.signEVP.sign_init()
        self.signEVP.sign_update(SHA.new(str(data)).digest())
        return self.signEVP.sign_final().encode('hex')

    # TO TEST
    def validSignedData(self, data, signature, certificate):
        pub_key = X509.load_cert_string(certificate.decode('hex')).get_pubkey()
        verifyEVP = EVP.PKey()
        verifyEVP.assign_rsa(pub_key)
        verifyEVP.verify_init()
        verifyEVP.verify_update(SHA.new(str(data)).digest())
        return verifyEVP.verify_final(signature.decode('hex'))
