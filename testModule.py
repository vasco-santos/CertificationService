import json
import Pyro4
from os.path import expanduser

from certModule.CertAuthority import CertificationAuthority
from certModule.CertSubject import CertificationSubject

home = expanduser("~")

ca = CertificationAuthority("ca_cert.pem", "ca_priv.pem", 'dioti')

cs = CertificationSubject("peer_cert.pub", "peer_priv.pem", "ca_cert.pem", 'dioti')