Hermes Connect --- RFC8994 Autonomic Control Plane
--------------------------------------------------


## Creating Certificates for each Host

In order to bring up the IPsec tunnels each host needs a certificate.
This certificate needs to be located in /etc/ipsec.d/certs/hostcert.pem.

For now, this certificate needs to be an RSA 2048 bit certificate, signed by an RSA certificate authority.  This limitation exists in the OpenswanX module, and it will get upgraded to do ECDSA and EdDSA keys in 2022.

All nodes in the ACP need to be signed by the same certificate authority.
The certificates need to include an emailAddress (rfc822Name SubjectAltName), which later will get replaced by an RFC8994 otherName (SAN).
The format for the content is specified in RFC8994, section 6.2.2.

The example below:

        Subject: emailAddress = "rfc8994+fd739fc23c3440112233445500000300+@acp.example.com"

has an IPv6 address fd73:9fc2:3c34:4011:2233:4455:0000:0300 embedded in it.
There are some details in section 6.11.
This above example address is an ACP-Vlong-8 address as it has a type of 1 (check this),
so the final "0300" represents host number "3" with 8 bits allocated to the host for
local host (a /112).

The RPL deamon (unstrung's sunshine) will accept the hostcert and extract this IP address out of it, configuring it on it's ACP interface, and advertising it to the rest of the network.

    # openssl x509 -inform der -noout -text -in /etc/ipsec.d/certs/hostcert.pem
    Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1426147312 (0x550147f0)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = ca, DC = sandelman, CN = fountain-test.example.com Unstrung Fountain Root CA
        Validity
            Not Before: May  7 19:21:21 2021 GMT
            Not After : Dec 31 00:00:00 2999 GMT
        Subject: emailAddress = "rfc8994+fd739fc23c3440112233445500000300+@acp.example.com"
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:bf:58:38:7e:c9:b0:7a:f1:71:e8:23:1e:82:69:
                    ...
                    07:7f
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                email:rfc8994+fd739fc23c3440112233445500000300+@acp.example.com
            X509v3 Basic Constraints:
                CA:FALSE
    Signature Algorithm: sha256WithRSAEncryption
         5e:5e:37:1f:50:95:3d:1d:b7:b6:da:43:25:ae:50:b4:92:dc:
         ...
         99:16:08:dd:34:b6


## Creating a new CSR manually

Normally the certificate would be created by processing an enrollment using an RFC8995's
Pledge Client.  But, in some debug cases a certificate is needed to be created manually.

    root@IETF-MACHINE-1:/etc/ipsec.d/private# openssl genrsa -out ietf1.pem 2048

    root@IETF-MACHINE-1:/etc/ipsec.d/private# openssl req -key ietf1.pem -subj \
       '/emailAddress=rfc8994+fd739fc23c3440112233445500000400+@acp.example.com' \
       -out ietf1.csr

The result is in the file "ietf1.csr" and this Certificate Signing Request should be transferred to a Registrar machine.  It may need to be turned from PEM to DER format:

    openssl req -outform der -in ietf1.csr -out ietf1.csr.der

Many Registrars will actually ignore the requested emailAddress, and assign their own ACPNodeName address to the node.

The resulting certificate needs to be installed into /etc/ipsec.d/certs/hostcert.pem

The registrar's Certification Authority (CA) certificate must be installed into /etc/ipsec.d/cacerts in order to anchor the resulting trust.


