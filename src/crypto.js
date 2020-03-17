'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const createHmac = require('create-hmac');
function hmacSHA512(key, data) {
  const hmac = createHmac('sha512', key);
  data.forEach(d => hmac.update(d));
  return hmac.digest();
}
exports.hmacSHA512 = hmacSHA512;
function hmacSHA256(key, data) {
  const hmac = createHmac('sha256', key);
  data.forEach(d => hmac.update(d));
  return hmac.digest();
}
exports.hmacSHA256 = hmacSHA256;
