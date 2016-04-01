# -*- coding: utf-8 -*-
"""
This module provides the necessary methods for a Certification Authority.
For creating the self signed Certificate for the CA, use the following command:

$ openssl req -x509 -newkey rsa:2048 -keyout ca_priv.pem -out ca_cert.pem

    @author: Vasco Santos
"""

import time

from M2Crypto import X509, RSA, EVP, BIO, ASN1


class CertificationAuthority(object):
    """ Class responsible for keeping the CA self-signed certificate,
    as well as, its private key.
    """

    def __init__(self, cert, priv_key, passphrase):
        """ Create a Certification Authority Object.

        Arguments:
            cert: file system path of the CA's self-signed certificate.
            priv_key: file system path of the CA's private key (encrypted).
            passphrase: Symmetric key for priv_key decryption.
        """

        def getPassphrase(*args):
            """ Callback for private key decrypting.
            """
            return str(passphrase.encode('utf-8'))

        self.cert = X509.load_cert(cert.encode('utf-8'))
        self.priv_key = RSA.load_key(priv_key.encode('utf-8'), getPassphrase)

        # Private key for signing
        self.signEVP = EVP.PKey()
        self.signEVP.assign_rsa(self.priv_key)

    def createSignedCertificate(self, subj_id, pub_key, expiration_time):
        """ Create a certificate for a subject public key, signed by the CA.

        Arguments:
            subj_id: certificate subject identifier.
            pub_key: public key of the subject.
            expiration_time: certificate life time.

        Returns:
            Certificate in PEM Format.
        """
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
        s_name.CN = str(subj_id)
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

    def getPublicKey(self):
        """ Get the CA Public Key.

        Returns:
            CA Public Key in PEM Format.
        """
        return self.cert.get_pubkey().get_rsa().as_pem().encode('hex')

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
        return cert.verify(self.cert.get_pubkey())

    def validSelfSignedCertificate(self):
        """ Verify if the self-signed CA certificate was not corrupted.

        Returns:
            true if the self signed certificate is valid, false otherwise.
        """
        return self.cert.check_ca() and self.cert.verify(self.cert.get_pubkey())

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

    def validSignedEncryptedData(self, cipherData, signature, certificate):
        """ Verify if the received data was signed by the owner of the certificate.

        Arguments:
            cipherData: data encrypted (base64 format).
            signature: digital signature of the data.
            certificate: certificate of the data issuer.

        Returns:
            true if the data maintains its integrity, false otherwise.
        """
        msgDigest = EVP.MessageDigest('sha1')
        msgDigest.update(cipherData.decode('base64'))
        pub_key = X509.load_cert_string(certificate.decode('hex')).get_pubkey().get_rsa()
        verifyEVP = EVP.PKey()
        verifyEVP.assign_rsa(pub_key)
        verifyEVP.verify_init()
        verifyEVP.verify_update(msgDigest.digest())
        return verifyEVP.verify_final(str(signature.decode('base64')))
