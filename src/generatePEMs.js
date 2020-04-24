import * as asn1js from 'asn1js';
import { version } from '../package.json';

export const OID_COUNTRY_NAME = "2.5.4.6";
export const OID_STATE_OR_PROVINCE_NAME = "2.5.4.8";
export const OID_LOCALITY_NAME = "2.5.4.7";
export const OID_ORGANIZATION_NAME = "2.5.4.10";
export const OID_ORGANIZATIONAL_UNIT_NAME = "2.5.4.11";
export const OID_COMMON_NAME = "2.5.4.3";
export const OID_EMAIL_ADDRESS = "1.2.840.113549.1.9.1";

function encodePem(data, label) {
  const stringData = String.fromCharCode.apply(null, new Uint8Array(data));
  const encodedData = btoa(stringData).replace(/.{64}/g, '$&\n');
  return `-----BEGIN ${label}-----\n${encodedData}\n-----END ${label}-----`;
}

function composeName(companyData){
  const attrubuteType = {
    [OID_COUNTRY_NAME]: asn1js.PrintableString,
    [OID_STATE_OR_PROVINCE_NAME]: asn1js.Utf8String,
    [OID_LOCALITY_NAME]: asn1js.Utf8String,
    [OID_ORGANIZATION_NAME]: asn1js.Utf8String,
    [OID_ORGANIZATIONAL_UNIT_NAME]: asn1js.Utf8String,
    [OID_COMMON_NAME]: asn1js.Utf8String,
    [OID_EMAIL_ADDRESS]: asn1js.IA5String
  };
  const attributesArr = Object.keys(companyData).map(oid => {
    return new asn1js.Set({
      value: [
        new asn1js.Sequence({
          value: [
            new asn1js.ObjectIdentifier({ value: oid }),
            new attrubuteType[oid]({ value: companyData[oid] })
          ]
        })
      ]
    });
  });
  return new asn1js.Sequence({ value: attributesArr});
}

function encodeCSR(pubKey, privKey, companyData){
  return new Promise(resolve => {
    crypto.subtle.exportKey("spki", pubKey).then(spkiBin => {
      let SubjectPublicKeyInfo = asn1js.fromBER(spkiBin).result;
      let zeroTagBuf = new Uint8Array([0xa0, 0x00]); //empty constructed context-specific class with tag 0
      let zeroTag = asn1js.fromBER(zeroTagBuf.buffer).result;
      let CertificationRequestInfo = new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: 0 }),
          composeName(companyData),
          SubjectPublicKeyInfo,
          zeroTag
        ]
      });

      let algorithm = new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.13" }),
          new asn1js.Null()
        ]
      });

      crypto.subtle.sign("RSASSA-PKCS1-v1_5", privKey, CertificationRequestInfo.toBER(false)).then(Signature => {
        let CertificationRequest = new asn1js.Sequence({
          value: [
            CertificationRequestInfo,
            algorithm,
            new asn1js.BitString({ valueHex: Signature })
          ]
        });
        resolve(encodePem(CertificationRequest.toBER(false), "CERTIFICATE REQUEST"));
      });
    });
  });
}

export function generatePrivateKeyAndCSR(companyData) {
  const keyGenParams = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 4096,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: "SHA-512"
  };
  const keyUsages = ["sign"];
  return new Promise(resolve => {
    crypto.subtle.generateKey(keyGenParams, true, keyUsages).then(keyPair => {
      crypto.subtle.exportKey("pkcs8", keyPair.privateKey).then(privKeyBuf => {
        let  privateKeyPEM = encodePem(privKeyBuf, "PRIVATE KEY");
        encodeCSR(keyPair.publicKey, keyPair.privateKey, companyData).then(CSR_PEM => {
          resolve({
            CSR_PEM: CSR_PEM,
            privateKeyPEM: privateKeyPEM
          });
        });
      });
    });
  });
}