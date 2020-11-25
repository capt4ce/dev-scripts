# pip install ecdsa
# pip install cryptography


# https://github.com/warner/python-ecdsa
# https://cryptography.io/en/latest/

from ecdsa import VerifyingKey, BadSignatureError, util

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat 
from cryptography.hazmat.primitives.serialization import Encoding
import hashlib

message = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.".encode('utf-8')
print(hashlib.sha256(message).hexdigest())

# getting verifying key from public key from PEM
# pem_data='''-----BEGIN CERTIFICATE-----
# MIIDzjCCAzCgAwIBAgIQCRxwO6tzCWdc73UTenfjrDAKBggqhkjOPQQDBDBYMQsw
# CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh
# DA5OVFJFRS0xMDc0NzAxMzETMBEGA1UEAwwKRVNURUlEMjAxODAeFw0xOTA1MzAw
# NjE1NDdaFw0yNDA1MjkyMTU5NTlaMHcxCzAJBgNVBAYTAkVFMSYwJAYDVQQDDB1D
# QVBPRElFQ0ksUk9CRVJUTywzNzQwNjI1MDE2MDESMBAGA1UEBAwJQ0FQT0RJRUNJ
# MRAwDgYDVQQqDAdST0JFUlRPMRowGAYDVQQFExFQTk9FRS0zNzQwNjI1MDE2MDB2
# MBAGByqGSM49AgEGBSuBBAAiA2IABKzxa/lg5nl5k6f9CK1EZP3gt+7+VD0RlVLE
# 0eeG3YUZA6/pJawUFM76rHQcUgD6ksXzejCodDD8WbtUP/doo8vJNFSHdLVkWywy
# CbKpKMHLe1LCu5c2kN3ffDSFhZB7J6OCAZ4wggGaMAkGA1UdEwQCMAAwDgYDVR0P
# AQH/BAQDAgZAMEgGA1UdIARBMD8wMgYLKwYBBAGDkSEBAQQwIzAhBggrBgEFBQcC
# ARYVaHR0cHM6Ly93d3cuc2suZWUvQ1BTMAkGBwQAi+xAAQIwHQYDVR0OBBYEFI3A
# VTKnMdqw1j/upmDPfzO1AQ//MIGKBggrBgEFBQcBAwR+MHwwCAYGBACORgEBMAgG
# BgQAjkYBBDATBgYEAI5GAQYwCQYHBACORgEGATBRBgYEAI5GAQUwRzBFFj9odHRw
# czovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNl
# cnRpZmljYXRlcy8TAkVOMB8GA1UdIwQYMBaAFNmscNtffr6U+KDkvkei0DStmioS
# MGYGCCsGAQUFBwEBBFowWDAnBggrBgEFBQcwAYYbaHR0cDovL2FpYS5zay5lZS9l
# c3RlaWQyMDE4MC0GCCsGAQUFBzAChiFodHRwOi8vYy5zay5lZS9lc3RlaWQyMDE4
# LmRlci5jcnQwCgYIKoZIzj0EAwQDgYsAMIGHAkIBICcDVSlZ2I/+A5SGrS1mNpQy
# W8Amz1EUslE5PkQ5kWlEId2jNfXTa48GiZYDE8sOBDu36xd+LH2N+EtJj2/SubAC
# QXsj+LaIjP1Cu3JccZ0+132dJxf3PhanZ4cmp2Q4Qmta0hQ7NlV0tl+MFFJASU0c
# vGGclxtDy+1uDwnqtDB5wYbg
# -----END CERTIFICATE-----'''
# cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), default_backend())
# pubKey_data = cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
# vk = VerifyingKey.from_pem(pubKey_data)

signature = '06C57BA074F7DE0B0D46F7C81E57CD183C728AF50EB96A1E5BD3D489A662A174AFD99F4E64238EF95D8433521423047B4B9E724552E398FF77FBEB2E850FCD76C91F6664EE248B542967108000E5325B6A278428218C643635118A6ACCCC4C38'

# getting verifying key from public key DER
publicKeyHexString = "3076301006072a8648ce3d020106052b8104002203620004acf16bf960e6797993a7fd08ad4464fde0b7eefe543d119552c4d1e786dd851903afe925ac1414cefaac741c5200fa92c5f37a30a87430fc59bb543ff768a3cbc934548774b5645b2c3209b2a928c1cb7b52c2bb973690dddf7c348585907b27"
vk = VerifyingKey.from_der(bytes.fromhex(publicKeyHexString))

sig = bytes.fromhex(signature)

print(vk.curve)
print(vk.to_string().hex())

try:
    vk.verify(sig, message, hashfunc=hashlib.sha256)
    print("\nRESULT: good signature\n")
except BadSignatureError:
    print("\nRESULT: BAD SIGNATURE\n")

r,s = util.sigdecode_string(sig,vk.curve.order)
print('signature R: ',r)
print('signature S: ',s)