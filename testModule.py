import json
import Pyro4
from os.path import expanduser

from certModule.CertAuthority import CertificationAuthority
from certModule.CertSubject import CertificationSubject

home = expanduser("~")


ca = CertificationAuthority("ca_cert.pem", "ca_priv.pem", 'dioti')
print("Certification Authority started...")

cs = CertificationSubject("peer_cert.pem", "peer_priv.pem", "ca_cert.pem", 'dioti')
print("Certification Subject Started...")

if ca.validSelfSignedCertificate():
    print("CA: Valid CA Auto Signed Certificate")

    if cs.validCertificationAuthorityCertificate():
        print ("CS: Valid CA Received Certification")

        data = ['aaa', 'bbb']

        # CA Sign
        signature = ca.signData(json.dumps(data))
        print ("CA: Data Signed")

        if cs.validCertificateAuthoritySignedData(json.dumps(data), signature):
            print("CS: Valid Data Signed Received")

        pub_key = cs.getPublicKey()
        print("CS: Received Public Key")

        peer_cert = ca.createSignedCertificate("awda10wd25aw5d1wa", pub_key, 60)
        print("CA: Created Signed Certificate for Peer")

        if cs.validCertificate(peer_cert):
            print("CS: Certificate is valid")

            # Peer Sign
            signature = cs.signData(json.dumps(data))
            print ("CS: Data Signed")

            if ca.validCertificate(peer_cert) and \
                    ca.validSignedData(json.dumps(data), signature, peer_cert):
                print("CA: Valid Data Signed Received")
