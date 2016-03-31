import json
import Pyro4
from os.path import expanduser

from certModule.CertAuthority import CertificationAuthority
from certModule.CertSubject import CertificationSubject

home = expanduser("~")

ca = CertificationAuthority("ca_cert.pem", "ca_priv.pem", 'dioti')
print("Certification Authority started...")

cs = CertificationSubject("peer_cert.pub", "peer_priv.pem", "ca_cert.pem", 'dioti')
print("Certification Subject Started...")

if ca.validSelfSignedCertificate():
    print("CA: Valid CA Auto Signed Certificate")

    if cs.validCertificationAuthorityCertificate():
        print ("CS: Valid CA Received Certification")

        data = ['aaa', 'bbb']
        signature = ca.signData(json.dumps(data))
        print ("CA: Data Signed")

        if cs.validCertificateAuthoritySignedData(json.dumps(data), signature):
            print("CS: Valid Data Signed Received")



