# -*- coding: utf-8 -*-
"""
This micro-service provides the necessary methods for a Certification Subject.
For creating the RSA Key Pair, use the following commands:

$ openssl genrsa -aes128 -passout pass:dioti -out peer_priv.pem 2048
$ openssl rsa -in peer_priv.pem -passin pass:dioti -pubout -out peer_cert.pem

    @author: Vasco Santos
"""

import Pyro4
from M2Crypto import X509, RSA, EVP


class CertificationSubject(object):
    """ Class responsible for keeping the Certification Subject Data, as well as,
    the Certification Authority Certificate.
    """

    def __init__(self, pub_key, priv_key, ca_cert, passphrase):
        """ Create a Certification Subject Object.

        Arguments:
            pub_key: file system path of the Subject's Public Key.
            priv_key: file system path of the Subject's Private Key (encrypted).
            ca_cert: file system path of the Certification Authority's Certificate.
            passphrase: Symmetric key for priv_key decryption.
        """
        def getPassphrase(*args):
            """ Callback for private key decrypting.
            """
            return str(passphrase.encode('utf-8'))

        self.pub_key = RSA.load_pub_key(pub_key.encode('utf-8'))
        self.priv_key = RSA.load_key(priv_key.encode('utf-8'), getPassphrase)
        self.ca_cert = X509.load_cert(ca_cert.decode('utf-8'))

        # Private key for signing
        self.signEVP = EVP.PKey()
        self.signEVP.assign_rsa(self.priv_key)

        # CA Key for validations
        self.verifyEVP = EVP.PKey()
        self.verifyEVP.assign_rsa(self.ca_cert.get_pubkey().get_rsa())

    def decryptData(self, data):
        """ Decrypt the intended data with the entity private key.

        Arguments:
            data: data to be decrypted.
        """
        return self.priv_key.private_decrypt(data.decode('base64'), RSA.pkcs1_padding)

    def encryptData(self, data, certificate):
        """ Encrypt the intended data with the public key contained in the certificate.

        Arguments:
            data: data to be encrypted.
            certificate: subject certificate.
        """
        cert = X509.load_cert_string(certificate.decode('hex'))
        return cert.get_pubkey().get_rsa().public_encrypt(str(data), RSA.pkcs1_padding).encode('base64')

    def encryptDataForCA(self, data):
        """ Encrypt the intended data with the public key of the Certification Authority.

        Arguments:
            data: data to be encrypted.
        """
        return self.ca_cert.get_pubkey().get_rsa().public_encrypt(str(data), RSA.pkcs1_padding).encode('base64')

    def getPublicKey(self):
        """ Get the Subject Public Key.

        Returns:
            CA Public Key in PEM Format.
        """
        return self.pub_key.as_pem().encode('hex')

    def signData(self, data):
        """ Sign a received String.

        Arguments:
            data: string to sign.

        Returns:
            signature of the received data.
        """
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(str(data))
        self.signEVP.sign_init()
        self.signEVP.sign_update(msgDigest.digest())
        return self.signEVP.sign_final().encode('base64')

    def signEncryptedData(self, cipherData):
        """ Sign encrypted data.

        Arguments:
            cipherData: data encrypted (base64 format).
        """
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(cipherData.decode('base64'))
        self.signEVP.sign_init()
        self.signEVP.sign_update(msgDigest.digest())
        return self.signEVP.sign_final().encode('base64')

    def validCertificate(self, certificate):
        """ Verify if a certificate of a subject was issued by this CA.

        Arguments:
            certificate: subject certificate.

        Returns:
            true if the certificate was issued by this CA. false otherwise.
        """
        cert = X509.load_cert_string(certificate.decode('hex'))
        # Data Analysis
        # Subject confirmation
        return cert.verify(self.ca_cert.get_pubkey())

    def validCertificationAuthorityCertificate(self):
        """ Verify if the self-signed CA certificate was not corrupted.

        Returns:
            true if the self signed certificate is valid, false otherwise.
        """
        return self.ca_cert.check_ca() and self.ca_cert.verify(self.ca_cert.get_pubkey())

    def validCertificateAuthoritySignedData(self, data, signature):
        """ Verify if the received data was signed by the CA.

        Arguments:
            data: received data.
            signature: digital signature of the data.

        Returns:
            true if the data maintains its integrity, false otherwise.
        """
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(str(data))
        self.verifyEVP.verify_init()
        self.verifyEVP.verify_update(msgDigest.digest())
        return self.verifyEVP.verify_final(signature.decode('base64'))

    def validCertificationAuthoritySignedEncryptedData(self, cipherData, signature):
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(cipherData.decode('base64'))
        self.verifyEVP.verify_init()
        self.verifyEVP.verify_update(msgDigest.digest())
        return self.verifyEVP.verify_final(signature.decode('base64'))

    def validSignedData(self, data, signature, certificate):
        """ Verify if the received data was signed by the owner of the certificate.

        Arguments:
            data: received data.
            signature: digital signature of the data.
            certificate: certificate of the data issuer.

        Returns:
            true if the data maintains its integrity, false otherwise.
        """
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(str(data))
        pub_key = X509.load_cert_string(certificate.decode('hex')).get_pubkey().get_rsa()
        verifyEVP = EVP.PKey()
        verifyEVP.assign_rsa(pub_key)
        verifyEVP.verify_init()
        verifyEVP.verify_update(msgDigest.digest())
        return verifyEVP.verify_final(str(signature.decode('base64')))


class Service(object):
    """ Remote Object service to be provided.
    """

    def build_CS(self, pub_key, priv_key, ca_cert, passphrase):
        """ Factory class responsible for creating the CA object.

        Arguments:
            pub_key: file system path of the Subject's Public Key.
            priv_key: file system path of the Subject's Private Key (encrypted).
            ca_cert: file system path of the Certification Authority's Certificate.
            passphrase: Symmetric key for priv_key decryption.
        """
        cs = CertificationSubject(pub_key, priv_key, ca_cert, passphrase)

        # Register object
        self._pyroDaemon.register(cs)
        return cs


# make a Pyro daemon
daemon = Pyro4.Daemon()
# find the name server
ns = Pyro4.locateNS()
# register the greeting maker as a Pyro object
uri = daemon.register(Service)
# register the object in the name server
ns.register("certificationService.CS", uri)
# start the event loop
daemon.requestLoop()
