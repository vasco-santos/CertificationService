import time
import Pyro4

from M2Crypto import X509, RSA, EVP, BIO, ASN1
from Crypto.Hash import SHA


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

    def signData(self, data):
        self.signEVP.sign_init()
        self.signEVP.sign_update(SHA.new(str(data)).digest())
        return self.signEVP.sign_final().encode('hex')

    # TO TEST
    def validSignedData(self, data, signature, certificate):
        pub_key = X509.load_cert_string(certificate.decode('hex')).get_pubkey().get_rsa()
        verifyEVP = EVP.PKey()
        verifyEVP.assign_rsa(pub_key)
        verifyEVP.verify_init()
        verifyEVP.verify_update(SHA.new(str(data)).digest())
        return verifyEVP.verify_final(signature.decode('hex'))

    def createignedCertificate(self, peer_id, peer_cert, expiration_time):
        # Public Key to certificate
        bio = BIO.MemoryBuffer(str(peer_cert))
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
