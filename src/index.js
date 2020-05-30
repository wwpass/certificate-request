import * as asn1js from 'asn1js';
import { version } from '../package.json';
import {
  generatePrivateKeyAndCSR,
  OID_COUNTRY_NAME,
  OID_STATE_OR_PROVINCE_NAME,
  OID_LOCALITY_NAME,
  OID_ORGANIZATION_NAME,
  OID_ORGANIZATIONAL_UNIT_NAME,
  OID_COMMON_NAME,
  OID_EMAIL_ADDRESS,
  OID_UNSTRUCTURED_NAME,
  OID_CHALLENGE_PASSWORD,
  OID_EXTENSION_REQUEST,
  EXTN_ID,
  CRITICAL,
  EXTN_VALUE
} from "./generatePEMs"

if ('console' in window && window.console.log) {
  window.console.log(`WWPass frontend library version ${version}`);
  window.console.log('Integer', asn1js.Integer);
  window.console.log(asn1js);
  let companyData = {
    [OID_COMMON_NAME]: "*.wikipedia.org",
    [OID_ORGANIZATION_NAME]: "Wikimedia Foundation, Inc.",
    [OID_ORGANIZATIONAL_UNIT_NAME]: "Finance",
    [OID_LOCALITY_NAME]: "San Francisco",
    [OID_STATE_OR_PROVINCE_NAME]: "California",
    [OID_COUNTRY_NAME]: "US",
    [OID_EMAIL_ADDRESS]: "none.none@wikipedia.org",
    [OID_EXTENSION_REQUEST]: [
      {
        [EXTN_ID]: "2.5.29.36",
        [CRITICAL]: false,
        [EXTN_VALUE]: new Uint8Array([48, 6, 2, 1, 1, 2, 1, 2]).buffer
      },
      {
        [EXTN_ID]: "2.5.29.19",
        [CRITICAL]: false,
        [EXTN_VALUE]: new Uint8Array([48, 6, 1, 1, 0, 2, 1, 0]).buffer
      }
    ],
    [OID_CHALLENGE_PASSWORD]: "qwerty",
    [OID_UNSTRUCTURED_NAME]: "Some Name"
  };
  generatePrivateKeyAndCSR(companyData).then(result => {
    addToPage(result.CSR_PEM);
    addToPage(result.privateKeyPEM);
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
