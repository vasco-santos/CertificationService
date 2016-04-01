"""
Example of a certification flow using the Certification Modules developed.

Execute name-server: pyro4-ns

    @author: Vasco Santos.
"""

import json
import Pyro4

# Get Service Remote Objects
service_ca = Pyro4.Proxy("PYRONAME:certificationService.CA")

service_cs = Pyro4.Proxy("PYRONAME:certificationService.CS")

# Instantiate the Entities.
ca = service_ca.build_CA("ca_cert.pem", "ca_priv.pem", 'dioti')
print("Certification Authority started...")

cs = service_cs.build_CS("peer_cert.pem", "peer_priv.pem", "ca_cert.pem", 'dioti')
print("Certification Subject Started...")

# Verify if the CA has self-signed certificate.
if ca.validSelfSignedCertificate():
    print("CA: Valid CA Auto Signed Certificate")

    # Verify if the CA has self-signed certificate.
    if cs.validCertificationAuthorityCertificate():
        print ("CS: Valid CA Received Certification")

        data = ['aaa', 'bbb']

        # CA Data signing.
        signature = ca.signData(json.dumps(data))
        print ("CA: Data Signed")

        # CS Signature Validation.
        if cs.validCertificateAuthoritySignedData(json.dumps(data), signature):
            print("CS: Valid Data Signed Received")

        cs_pub_key = cs.getPublicKey()
        print("CS: Received Public Key")

        # CA issues a subject certificate, signed with its private key.
        lifetime = 60
        peer_cert = ca.createSignedCertificate("awda10wd25aw5d1wa", cs_pub_key, lifetime)
        print("CA: Created Signed Certificate for Peer")

        # CS Validates its certificate (signed by the CA).
        if cs.validCertificate(peer_cert):
            print("CS: Certificate is valid")

            # CS Data Signing.
            signature = cs.signData(json.dumps(data))
            print ("CS: Data Signed")

            # CA Signature Validation.
            if ca.validCertificate(peer_cert) and \
                    ca.validSignedData(json.dumps(data), signature, peer_cert):
                print("CA: Valid Data Signed Received")

            # CIPHERS
            # CA Cipher Data.
            cipherData = ca.encryptData(json.dumps(data), peer_cert)
            print("CA: Data encrypted")

            # CA Data Encrypted Signing.
            cipherSignature = ca.signEncryptedData(cipherData)
            print("CA: Data Encrypted Signed")

            # CS Signature Validation for Encrypted Data.
            if cs.validCertificationAuthoritySignedEncryptedData(cipherData, cipherSignature):
                print("CS: Valid Data Encrypted Signed")

                decrypt_data = cs.decryptData(cipherData)
                print("CS: Data decrypted - " + str(decrypt_data))

            # CS Cipher Data.
            cipherData = cs.encryptDataForCA(json.dumps(data))
            print("CS: Data encrypted")

            # CS Data Encrypted Signing.
            cipherSignature = cs.signEncryptedData(cipherData)
            print("CS: Data Encrypted Signed")

            # CA Signature Validation for Encrypted Data.
            if ca.validSignedEncryptedData(cipherData, cipherSignature, peer_cert):
                print("CA: Valid Data Encrypted Signed")

                decrypt_data = ca.decryptData(cipherData)
                print("CA: Data decrypted - " + str(decrypt_data))
