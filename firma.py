#!/usr/bin/env python
# -*- coding: utf-8 -*-
u"""
Firma facturaE.xml
@author: juhegue mié ene  9 16:49:47 CET 2019

Página para chequear la factura firmada
http://sedeaplicaciones2.minetur.gob.es/FacturaE/
"""

__version__ = '0.0.1'

import base64
import datetime
import hashlib
from lxml import etree
from OpenSSL import crypto
import random
import urllib
import xmlsig


def parse_xml(name):
    return etree.parse(name).getroot()


def save_xml(name, data):
    with open(name, 'wb') as w:
        w.write(data)


def leecertificado(name):
    with open(name, 'rb') as f:
        return f.read()


def sign_file(cert, password, xml_firma):
    random_val = random.randint(1, 99999)

    signature_id = 'Signature-%s' % random_val
    signed_properties_id = 'SignedProperties-%s' % signature_id
    signature_value = 'SignatureValue-%s' % random_val
    qualifying_properties = 'QualifyingProperties-%05d' % random_val
    key_info_id = 'KeyInfoId-%s' % signature_id
    reference_id = 'Reference-%05d' % random_val
    object_id = 'XadesObjectId-%05d' % random_val

    xades = 'http://uri.etsi.org/01903/v1.3.2#'
    ds = 'http://www.w3.org/2000/09/xmldsig#'
    xades141 = 'http://uri.etsi.org/01903/v1.4.1#'
    sig_policy_identifier = 'http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf'
    sig_policy_hash_value = 'Ohixl6upD6av8N7pEvDABhEL6hM='

    root = xml_firma
    certificate = crypto.load_pkcs12(cert, password)

    sign = etree.Element(
        etree.QName(ds, 'Signature'),
        nsmap={'ds': ds, 'xades': 'http://uri.etsi.org/01903/v1.3.2#'},
        attrib={
            xmlsig.constants.ID_ATTR: signature_id,
        }
    )

    signed_info = etree.SubElement(
        sign,
        etree.QName(ds, 'SignedInfo')
    )

    etree.SubElement(
        signed_info,
        etree.QName(ds, 'CanonicalizationMethod'),
        attrib={
            'Algorithm': xmlsig.constants.TransformInclC14N
        }
    )

    etree.SubElement(
        signed_info,
        etree.QName(ds, 'SignatureMethod'),
        attrib={
            'Algorithm': xmlsig.constants.TransformRsaSha256
        }
    )

    reference = etree.SubElement(
        signed_info,
        etree.QName(ds, 'Reference'),
        attrib={
            xmlsig.constants.ID_ATTR: reference_id,
            'URI': ''
        }
    )

    transforms = etree.SubElement(
        reference,
        etree.QName(ds, 'Transforms'),
    )

    etree.SubElement(
        transforms,
        etree.QName(ds, 'Transform'),
        attrib={
            'Algorithm': 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
        }
    )

    etree.SubElement(
        reference,
        etree.QName(ds, 'DigestMethod'),
        attrib={
            'Algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256'
        }
    )

    etree.SubElement(
        reference,
        etree.QName(ds, 'DigestValue')
    )

    sec_reference = etree.SubElement(
        signed_info,
        etree.QName(ds, 'Reference'),
        attrib={
            xmlsig.constants.ID_ATTR: 'ReferenceKeyInfo',
            'URI': '#' + key_info_id

        }
    )

    etree.SubElement(
        sec_reference,
        etree.QName(ds, 'DigestMethod'),
        attrib={
            'Algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256'
        }
    )

    digest_value2 = hashlib.sha256(
       crypto.dump_certificate(
           crypto.FILETYPE_ASN1,
           certificate.get_certificate()
       )
    )

    etree.SubElement(
        sec_reference,
        etree.QName(ds, 'DigestValue')
    ).text = base64.b64encode(digest_value2.digest())

    tr_reference = etree.SubElement(
        signed_info,
        etree.QName(ds, 'Reference'),
        attrib={
            'Type': 'http://uri.etsi.org/01903#SignedProperties',
            'URI': '#' + signed_properties_id,
        }
    )

    etree.SubElement(
        tr_reference,
        etree.QName(ds, 'DigestMethod'),
        attrib={
            'Algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256'
        }
    )

    digest_value3 = hashlib.sha256(
       crypto.dump_certificate(
           crypto.FILETYPE_ASN1,
           certificate.get_certificate()
       )
    )

    etree.SubElement(
        tr_reference,
        etree.QName(ds, 'DigestValue')
    ).text = base64.b64encode(digest_value3.digest())

    etree.SubElement(
        sign,
        etree.QName(ds, 'SignatureValue'),
        attrib={
            xmlsig.constants.ID_ATTR: signature_value
        }
    )

    key_info = etree.SubElement(
        sign,
        etree.QName(ds, 'KeyInfo'),
        attrib={
            xmlsig.constants.ID_ATTR: key_info_id
        }
    )

    x509 = etree.SubElement(
        key_info,
        etree.QName(ds, 'X509Data'),
    )

    etree.SubElement(
        x509,
        etree.QName(ds, 'X509Certificate'),
    )

    etree.SubElement(
        key_info,
        etree.QName(ds, 'KeyValue'),
    )

    object_node = etree.SubElement(
        sign,
        etree.QName(xmlsig.constants.DSigNs, 'Object'),
        attrib={xmlsig.constants.ID_ATTR: object_id}
    )

    qualifying_properties = etree.SubElement(
        object_node,
        etree.QName(xades, 'QualifyingProperties'),
        nsmap={'xades': xades, 'xades141': xades141},
        attrib={
            xmlsig.constants.ID_ATTR: qualifying_properties,
            'Target': '#' + signature_id
        })

    signed_properties = etree.SubElement(
        qualifying_properties,
        etree.QName(xades, 'SignedProperties'),
        attrib={
            xmlsig.constants.ID_ATTR: signed_properties_id
        }
    )

    signed_signature_properties = etree.SubElement(
        signed_properties,
        etree.QName(xades, 'SignedSignatureProperties')
    )

    etree.SubElement(
        signed_signature_properties,
        etree.QName(xades, 'SigningTime')
    ).text = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S%z')

    signing_certificate = etree.SubElement(
        signed_signature_properties,
        etree.QName(xades, 'SigningCertificate')
    )

    signing_certificate_cert = etree.SubElement(
        signing_certificate,
        etree.QName(xades, 'Cert')
    )

    cert_digest = etree.SubElement(
        signing_certificate_cert,
        etree.QName(xades, 'CertDigest')
    )

    etree.SubElement(
        cert_digest,
        etree.QName(xmlsig.constants.DSigNs, 'DigestMethod'),
        attrib={
            'Algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256'
        }
    )

    hash_cert = hashlib.sha256(
        crypto.dump_certificate(
            crypto.FILETYPE_ASN1,
            certificate.get_certificate()
        )
    )

    etree.SubElement(
        cert_digest,
        etree.QName(xmlsig.constants.DSigNs, 'DigestValue')
    ).text = base64.b64encode(hash_cert.digest())

    issuer_serial = etree.SubElement(
        signing_certificate_cert,
        etree.QName(xades, 'IssuerSerial')
    )

    etree.SubElement(
        issuer_serial,
        etree.QName(xmlsig.constants.DSigNs, 'X509IssuerName')
    ).text = xmlsig.utils.get_rdns_name(certificate.get_certificate().to_cryptography().issuer.rdns)

    etree.SubElement(
        issuer_serial,
        etree.QName(xmlsig.constants.DSigNs, 'X509SerialNumber')
    ).text = str(certificate.get_certificate().get_serial_number())

    signature_policy_identifier = etree.SubElement(
        signed_signature_properties,
        etree.QName(xades, 'SignaturePolicyIdentifier')
    )

    signature_policy_id = etree.SubElement(
        signature_policy_identifier,
        etree.QName(xades, 'SignaturePolicyId')
    )

    sig_policy_id = etree.SubElement(
        signature_policy_id,
        etree.QName(xades, 'SigPolicyId')
    )

    etree.SubElement(
        sig_policy_id,
        etree.QName(xades, 'Identifier')
    ).text = sig_policy_identifier

    etree.SubElement(
        sig_policy_id,
        etree.QName(xades, 'Description')
    ).text = 'facturae31'

    sig_policy_hash = etree.SubElement(
        signature_policy_id,
        etree.QName(xades, 'SigPolicyHash')
    )

    etree.SubElement(
        sig_policy_hash,
        etree.QName(xmlsig.constants.DSigNs, 'DigestMethod'),
        attrib={
            'Algorithm': 'http://www.w3.org/2000/09/xmldsig#sha1'
        })

    try:
        remote = urllib.urlopen(sig_policy_identifier)
        hash_value = base64.b64encode(hashlib.sha1(remote.read()).digest())
    except Exception as e:
        hash_value = sig_policy_hash_value

    etree.SubElement(
        sig_policy_hash,
        etree.QName(xmlsig.constants.DSigNs, 'DigestValue')
    ).text = hash_value

    etsi = xades
    signer_role = etree.SubElement(
       signed_signature_properties,
       etree.QName(etsi, 'SignerRole')
    )
    claimed_roles = etree.SubElement(
       signer_role,
       etree.QName(etsi, 'ClaimedRoles')
    )

    etree.SubElement(
       claimed_roles,
       etree.QName(etsi, 'ClaimedRole')
    ).text = 'emisor'

    ctx = xmlsig.SignatureContext()
    key = crypto.load_pkcs12(cert, password)
    ctx.x509 = key.get_certificate().to_cryptography()
    ctx.public_key = ctx.x509.public_key()
    ctx.private_key = key.get_privatekey().to_cryptography_key()

    # print (etree.tostring(sign))
    root.append(sign)
    ctx.sign(sign)

    return etree.tostring(root, encoding='UTF-8', xml_declaration=True, standalone=False)


def firma_xml(certificado, clave, factura_xml, factura_xml_firmada):
    sig_xml = sign_file(leecertificado(certificado), clave, parse_xml(factura_xml))
    save_xml(factura_xml_firmada, sig_xml)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, )
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-o', dest='origen', type=str, required=True, help='factura xml origen.')
    parser.add_argument('-d', dest='destino', type=str, required=False, help='factura xml destino.')
    parser.add_argument('-c', dest='certificado', type=str, required=True, help='certificado.')
    parser.add_argument('-p', dest='clave', type=str, required=True, help='clave.')
    args = parser.parse_args()
    try:
        sig_xml = sign_file(leecertificado(args.certificado), str.encode(args.clave), parse_xml(args.origen))
        save_xml(args.destino or args.origen, sig_xml)
    except crypto.Error as e:
        print ('Error en certificado/clave')
    except IOError as e:
        print ('%s' % e)
