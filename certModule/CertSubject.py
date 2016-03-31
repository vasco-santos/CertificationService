import Pyro4

from M2Crypto import X509, RSA, EVP, BIO, ASN1


class CertificationSubject(object):

    def __init__(self, cert, priv_key, ca_cert, passphrase):

        def getPassphrase(*args):
            return str(passphrase.encode('utf-8'))

        self.cert = RSA.load_pub_key(cert.encode('utf-8'))
        self.priv_key = RSA.load_key(priv_key.encode('utf-8'), getPassphrase)
        self.ca_cert = X509.load_cert(ca_cert.decode('utf-8'))

        # Private key for signing
        self.signEVP = EVP.PKey()
        self.signEVP.assign_rsa(self.priv_key)

        # CA Key for validations
        self.verifyEVP = EVP.PKey()
        self.verifyEVP.assign_rsa(self.ca_cert.get_pubkey().get_rsa())


    def validCertificationAuthorityCertificate(self):
        return self.ca_cert.check_ca() and self.ca_cert.verify(self.ca_cert.get_pubkey())

    def validCertificate(self, certificate):
        cert = X509.load_cert_string(certificate.decode('hex'))
        return cert.verify(self.ca_cert.get_pubkey())

    def signData(self, data):
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(str(data))
        self.signEVP.sign_init()
        self.signEVP.sign_update(msgDigest.digest())
        return self.signEVP.sign_final().encode('base64')

    def validSignedData(self, data, signature, certificate):
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(str(data))
        pub_key = X509.load_cert_string(certificate.decode('hex')).get_pubkey().get_rsa()
        verifyEVP = EVP.PKey()
        verifyEVP.assign_rsa(pub_key)
        verifyEVP.verify_init()
        verifyEVP.verify_update(msgDigest.digest())
        return verifyEVP.verify_final(str(signature.decode('base64')))

    def validCertificateAuthoritySignedData(self, data, signature):
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(str(data))
        self.verifyEVP.verify_init()
        self.verifyEVP.verify_update(msgDigest.digest())
        return self.verifyEVP.verify_final(signature.decode('base64'))

    def getPublicKey(self):
        return self.cert.as_pem().encode('hex')
