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
} from './generatePEMs'

if ('console' in window && window.console.log) {
  window.console.log(`WWPass frontend library version ${version}`);
}