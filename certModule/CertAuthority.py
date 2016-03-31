import time
import Pyro4

from M2Crypto import X509, RSA, EVP, BIO, ASN1


class CertificationAuthority(object):

    def __init__(self, cert, priv_key, passphrase):

        def getPassphrase(*args):
            return str(passphrase.encode('utf-8'))

        self.cert = X509.load_cert(cert.encode('utf-8'))
        self.priv_key = RSA.load_key(priv_key.encode('utf-8'), getPassphrase)
        # Private key for signing
        self.signEVP = EVP.PKey()
        self.signEVP.assign_rsa(self.priv_key)

    def validSelfSignedCertificate(self):
        return self.cert.check_ca() and self.cert.verify(self.cert.get_pubkey())

    def validCertificate(self, certificate):
        cert = X509.load_cert_string(certificate.decode('hex'))
        return cert.verify(self.cert.get_pubkey())

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

    def createSignedCertificate(self, peer_id, pub_key, expiration_time):
        # Public Key to certificate
        bio = BIO.MemoryBuffer(str(pub_key.decode('hex')))
        pub_key = RSA.load_pub_key_bio(bio)
        pkey = EVP.PKey()
        pkey.assign_rsa(pub_key)

        # Certificate Fields
        cur_time = ASN1.ASN1_UTCTIME()
        cur_time.set_time(int(time.time()))
        expire_time = ASN1.ASN1_UTCTIME()
        expire_time.set_time(int(time.time()) + expiration_time * 60) # In expiration time minutes

        # Certification Creation
        cert = X509.X509()
        cert.set_pubkey(pkey)
        s_name = X509.X509_Name()
        s_name.C = "PT"
        s_name.CN = str(peer_id)
        cert.set_subject(s_name)
        i_name = X509.X509_Name()
        i_name.C = "PT"
        i_name.CN = "Register Server"
        cert.set_issuer_name(i_name)
        cert.set_not_before(cur_time)
        cert.set_not_after(expire_time)
        cert.sign(self.signEVP, md="sha1")
        #cert.save_pem("peer_CA.pem")
        return cert.as_pem().encode('hex')

    def getPublicKey(self):
        return self.cert.get_pubkey().get_rsa().as_pem().encode('hex')
