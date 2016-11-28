"""
Create certificates and private keys for the 'simple' example.
"""

from __future__ import print_function

from OpenSSL import crypto
from certgen import (
    createKeyPair,
    createCertRequest,
    createCertificate,
)
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("cn", type=str, help="certficate common name")
args = parser.parse_args()

with open('simple/CA.cert', 'rt') as ca:
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.read())

with open('simple/CA.pkey', 'rt') as capkey:
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, capkey.read())


for (fname, cname) in [('client', args.cn)]:
    pkey = createKeyPair(crypto.TYPE_RSA, 2048)
    req = createCertRequest(pkey, CN=cname)
    # Certificates are valid for five years.
    cert = createCertificate(req, (cacert, cakey), 1, (0, 60*60*24*365*5))

    print('Creating Certificate %s private key in "simple/%s.pkey"'
          % (fname, fname))
    with open('simple/%s.pkey' % (fname,), 'w') as leafpkey:
        leafpkey.write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode('utf-8')
        )

    print('Creating Certificate %s certificate in "simple/%s.cert"'
          % (fname, fname))
    with open('simple/%s.cert' % (fname,), 'w') as leafcert:
        leafcert.write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
        )
