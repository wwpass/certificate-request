import * as asn1js from 'asn1js';

const OID_COUNTRY_NAME = '2.5.4.6';
const OID_STATE_OR_PROVINCE_NAME = '2.5.4.8';
const OID_LOCALITY_NAME = '2.5.4.7';
const OID_ORGANIZATION_NAME = '2.5.4.10';
const OID_ORGANIZATIONAL_UNIT_NAME = '2.5.4.11';
const OID_COMMON_NAME = '2.5.4.3';
const pkcs9 = '1.2.840.113549.1.9.';
const OID_EMAIL_ADDRESS = `${pkcs9}1`;

const OID_UNSTRUCTURED_NAME = `${pkcs9}2`;
const OID_CHALLENGE_PASSWORD = `${pkcs9}7`;
const OID_EXTENSION_REQUEST = `${pkcs9}14`;

export const OID = {
  OID_COUNTRY_NAME,
  OID_STATE_OR_PROVINCE_NAME,
  OID_LOCALITY_NAME,
  OID_ORGANIZATION_NAME,
  OID_ORGANIZATIONAL_UNIT_NAME,
  OID_COMMON_NAME,
  OID_EMAIL_ADDRESS,
  OID_UNSTRUCTURED_NAME,
  OID_CHALLENGE_PASSWORD,
  OID_EXTENSION_REQUEST
};

const EXTN_ID = 'extnId';
const CRITICAL = 'criticald';
const EXTN_VALUE = 'extnValue';

export const EXTN_LABELS = {
  EXTN_ID,
  CRITICAL,
  EXTN_VALUE
};

function encodePem(data, label) {
  const stringData = String.fromCharCode.apply(null, new Uint8Array(data));
  const encodedData = btoa(stringData).replace(/.{64}/g, '$&\n');
  return `-----BEGIN ${label}-----\n${encodedData}\n-----END ${label}-----`;
}

function composeAttribute(companyData) {
  const attributesData = [];
  if (OID_UNSTRUCTURED_NAME in companyData) {
    attributesData.push(
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_UNSTRUCTURED_NAME }),
          new asn1js.Set({
            value: [
              new asn1js.Utf8String({
                value: companyData[OID_UNSTRUCTURED_NAME]
              })
            ]
          })
        ]
      })
    );
  }
  if (OID_CHALLENGE_PASSWORD in companyData) {
    const expr = /^[-a-zA-Z0-9/:=,' ()+.?]*$/;
    let passwd;
    if (companyData[OID_CHALLENGE_PASSWORD].match(expr)) {
      passwd = new asn1js.PrintableString({ value: companyData[OID_CHALLENGE_PASSWORD] });
    } else {
      passwd = new asn1js.Utf8String({ value: companyData[OID_CHALLENGE_PASSWORD] });
    }
    attributesData.push(
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_CHALLENGE_PASSWORD }),
          new asn1js.Set({ value: [passwd] })
        ]
      })
    );
  }
  if (OID_EXTENSION_REQUEST in companyData) {
    attributesData.push(
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_EXTENSION_REQUEST }),
          new asn1js.Set({
            value:
            companyData[OID_EXTENSION_REQUEST].map((entry) => new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: entry[EXTN_ID] }),
                new asn1js.Boolean({ value: entry[CRITICAL] }),
                new asn1js.OctetString({ valueHex: entry[EXTN_VALUE] })
              ]
            }))
          })
        ]
      })
    );
  }
  if (attributesData.length > 0) {
    const attributesBuf = new Uint8Array([0xa0, 0x00]);
    // empty constructed context-specific class with tag 0
    const attributes = asn1js.fromBER(attributesBuf.buffer).result;
    attributesData.forEach((item) => {
      attributes.valueBlock.value.push(item);
    });
    return attributes;
  }
  return null;
}

function composeName(companyData) {
  const attrubuteType = {
    [OID_COUNTRY_NAME]: asn1js.PrintableString,
    [OID_STATE_OR_PROVINCE_NAME]: asn1js.Utf8String,
    [OID_LOCALITY_NAME]: asn1js.Utf8String,
    [OID_ORGANIZATION_NAME]: asn1js.Utf8String,
    [OID_ORGANIZATIONAL_UNIT_NAME]: asn1js.Utf8String,
    [OID_COMMON_NAME]: asn1js.Utf8String,
    [OID_EMAIL_ADDRESS]: asn1js.IA5String
  };
  const companyDataKeys = Object.keys(companyData).filter((oid) => oid in attrubuteType);
  const attributesArr = companyDataKeys.map((oid) => new asn1js.Set({
    value: [
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: oid }),
          new attrubuteType[oid]({ value: companyData[oid] })
        ]
      })
    ]
  }));
  return new asn1js.Sequence({ value: attributesArr });
}

function encodeCSR(pubKey, privKey, companyData) {
  return new Promise((resolve) => {
    crypto.subtle.exportKey('spki', pubKey).then((spkiBin) => {
      const SubjectPublicKeyInfo = asn1js.fromBER(spkiBin).result;
      const CertificationRequestInfo = new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: 0 }),
          composeName(companyData),
          SubjectPublicKeyInfo
        ]
      });

      const attributes = composeAttribute(companyData);
      if (attributes != null) {
        CertificationRequestInfo.valueBlock.value.push(attributes);
      }

      const algorithm = new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.1.13' }),
          new asn1js.Null()
        ]
      });

      crypto.subtle.sign('RSASSA-PKCS1-v1_5', privKey, CertificationRequestInfo.toBER(false)).then((Signature) => {
        const CertificationRequest = new asn1js.Sequence({
          value: [
            CertificationRequestInfo,
            algorithm,
            new asn1js.BitString({ valueHex: Signature })
          ]
        });
        resolve(encodePem(CertificationRequest.toBER(false), 'CERTIFICATE REQUEST'));
      });
    });
  });
}

export function generatePrivateKeyAndCSR(companyData) {
  const keyGenParams = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 4096,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: 'SHA-512'
  };
  const keyUsages = ['sign'];
  return new Promise((resolve) => {
    crypto.subtle.generateKey(keyGenParams, true, keyUsages).then((keyPair) => {
      crypto.subtle.exportKey('pkcs8', keyPair.privateKey).then((privKeyBuf) => {
        const privateKeyPEM = encodePem(privKeyBuf, 'PRIVATE KEY');
        encodeCSR(keyPair.publicKey, keyPair.privateKey, companyData).then((CSR_PEM) => {
          resolve({
            CSR_PEM,
            privateKeyPEM
          });
        });
      });
    });
  });
}
