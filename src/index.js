import * as asn1js from 'asn1js';
import { version } from '../package.json';

if ('console' in window && window.console.log) {
  window.console.log(`WWPass frontend library version ${version}`);
  window.console.log('Integer', asn1js.Integer);
  window.console.log(asn1js);
  let companyData = {
    commonName: "*.wikipedia.org",
    organizationName: "Wikimedia Foundation, Inc.",
    organizationalUnitName: "Finance",
    localityName: "San Francisco",
    stateOrProvinceName: "California",
    countryName: "US",
    emailAddress: "none.none@wikipedia.org"
  };
  generatePEMs(companyData).then(result => {
    addToPage(result.CSR_PEM);
    addToPage(result.privateKeyPEM);
  });
}

function encodePem(data, label) {
  const stringData = String.fromCharCode.apply(null, new Uint8Array(data));
  const encodedData = btoa(stringData).replace(/.{64}/g, '$&\n');
  return `-----BEGIN ${label}-----\n${encodedData}\n-----END ${label}-----`;
}

function encodeCSR(pubKey, privKey, companyData){
  return new Promise(resolve => {
    let name = new asn1js.Sequence({
      value: [
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.6" }),
                new asn1js.PrintableString({ value: companyData.countryName })
              ]
            })
          ]
        }),
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.8" }),
                new asn1js.Utf8String({ value: companyData.stateOrProvinceName })
              ]
            })
          ]
        }),
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.7" }),
                new asn1js.Utf8String({ value: companyData.localityName })
              ]
            })
          ]
        }),
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.10" }),
                new asn1js.Utf8String({ value: companyData.organizationName })
              ]
            })
          ]
        }),
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.11" }),
                new asn1js.Utf8String({ value: companyData.organizationalUnitName })
              ]
            })
          ]
        }),
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                new asn1js.Utf8String({ value: companyData.commonName })
              ]
            })
          ]
        }),
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.9.1" }),
                new asn1js.IA5String({ value: companyData.emailAddress })
              ]
            })
          ]
        })
      ]
    });

    crypto.subtle.exportKey("spki", pubKey).then(spkiBin => {
      let SubjectPublicKeyInfo = asn1js.fromBER(spkiBin).result;
      let zeroTagBuf = new Uint8Array([0xa0, 0x00]); //empty constructed context-specific class with tag 0
      let zeroTag = asn1js.fromBER(zeroTagBuf.buffer).result;
      let CertificationRequestInfo = new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: 0 }),
          name,
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

function generatePEMs(companyData) {
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

function addToPage(text){
  var outer = document.createElement('div');
  var inner = document.createElement('code');
  inner.style.cssText = 'white-space: pre-wrap;';
  inner.textContent = text;
  outer.appendChild(inner);
  document.body.appendChild(outer);
}
