# Certification Service for Python

## Motivation

This Service was developing in order to overtake some limitations of the Security Libraries for Python. 
The M2Crypto library consists on a Python wrapper for OpenSSL featuring X509, RSA, among other features. However, the majority of the Cryptographic libraries for python, such as this library, are not fully supported by Python3. Therefore, the developed service uses Pyro4 in order to allow Remote Objects (running in python2) to be used in python3 applications.
In addition, this service also consists on an abstraction layer for the complex, as well as not properly documented, M2Crypto library.

This repository also contains the mentioned Remote Objects in traditional modules, which can be imported like the traditional python modules.

## Service Structure
 
This service is composed by two different remote objects. A module for a Certification Authority(CA), as well as a module for Certification Subjects (CS).
The CA needs a self-signed certificate, as well as a Private Key. Moreover, the CA needs the CA certificate, as well as a RSA Key pair.

It is important to refer that the certificates and keys mentioned should be generated using OpenSSL.

## Dependencies

The Certification services and modules have the following dependencies:

```
Python 2.7
M2Crypto
OpenSSL
Pyro4
```

The test examples have the following dependencies:

```
Python 2.7 or Python 3
Pyro4
```

## Generating OpenSSL Certificate and Key Pairs

Considering the Certification Authority, the following command should be executed:

```
$ openssl req -x509 -newkey rsa:2048 -keyout ca_priv.pem -out ca_cert.pem
```

Considering the Certification Subject, the following commands should be executed:

```
$ openssl genrsa -aes128 -passout pass:dioti -out peer_priv.pem 2048
$ openssl rsa -in peer_priv.pem -passin pass:dioti -pubout -out peer_cert.pem
```

## Example for Traditional Module

Considering the python script testModule, it is necessary to execute the following command:

```
python2.7 testModule.py
```

## Example for Remote Objects Service

Considering the python script testService, it is necessary to execute the following commands:

```
pyro4-ns
python2.7 certRemoteObjects/CertAuthoritpy
python2.7 certRemoteObjects/CertSubject.py
python testService.py
```
