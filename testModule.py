# -*- coding: utf-8 -*-
"""
Example of a certification flow using the Certification Modules developed.

    @author: Vasco Santos.
"""

import json

from certModule.CertAuthority import CertificationAuthority
from certModule.CertSubject import CertificationSubject


# Instantiate the Entities.
ca = CertificationAuthority("ca_cert.pem", "ca_priv.pem", 'dioti')
print("Certification Authority started...")

cs = CertificationSubject("peer_cert.pem", "peer_priv.pem", "ca_cert.pem", 'dioti')
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

        pub_key = cs.getPublicKey()
        print("CS: Received Public Key")

        # CA issues a subject certificate, signed with its private key.
        lifetime = 60
        peer_cert = ca.createSignedCertificate("awda10wd25aw5d1wa", pub_key, lifetime)
        print("CA: Created Signed Certificate for Peer")

        # CS Validates its certificate (signed by the CA).
        if cs.validCertificate(peer_cert):
            print("CS: Certificate is valid")

            # CS Data Signing-
            signature = cs.signData(json.dumps(data))
            print ("CS: Data Signed")

            # CA Signature Validation.
            if ca.validCertificate(peer_cert) and \
                    ca.validSignedData(json.dumps(data), signature, peer_cert):
                print("CA: Valid Data Signed Received")
