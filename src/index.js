import { version } from '../package.json';
import {
  generatePrivateKeyAndCSR,
  OID,
  EXTN_LABELS
} from './generatePEMs';

if ('console' in window && window.console.log) {
  window.console.log(`WWPass frontend library version ${version}`);
}

window.PEM = {
  generate: generatePrivateKeyAndCSR,
  OID,
  EXTN_LABELS
};
