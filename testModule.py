import json
import Pyro4
from os.path import expanduser

from certModule.CertAuthority import CertificationAuthority
from certModule.CertSubject import CertificationSubject

home = expanduser("~")

ca = CertificationAuthority("ca_cert.pem", "ca_priv.pem", 'dioti')
print("Certification Authority started...")

if ca.validSelfSignedCertificate():
    print("CA: Valid CA Auto Signed Certificate")

    cs = CertificationSubject("peer_cert.pub", "peer_priv.pem", "ca_cert.pem", 'dioti')
    print("Certification Subject Started...")

    if cs.validCertificationAuthorityCertificate():
        print ("CS: Valid CA Received Certification")

        



