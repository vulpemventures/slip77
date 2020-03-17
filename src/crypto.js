'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const createHmac = require('create-hmac');
function hmacSHA512(key, data) {
  return createHmac('sha512', key)
    .update(data)
    .digest();
}
exports.hmacSHA512 = hmacSHA512;
function hmacSHA256(key, data) {
  return createHmac('sha256', key)
    .update(data)
    .digest();
}
exports.hmacSHA256 = hmacSHA256;
