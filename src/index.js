import * as asn1js from 'asn1js';
import { version } from '../package.json';

if ('console' in window && window.console.log) {
  window.console.log(`WWPass frontend library version ${version}`);
  window.console.log('Integer', asn1js.Integer);
  window.console.log(asn1js);
}

// здесь пишем вспомогательные функции
