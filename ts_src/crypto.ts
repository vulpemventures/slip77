const createHmac = require('create-hmac');

export function hmacSHA512(key: Buffer, data: Buffer): Buffer {
  return createHmac('sha512', key)
    .update(data)
    .digest();
}

export function hmacSHA256(key: Buffer, data: Buffer): Buffer {
  return createHmac('sha256', key)
    .update(data)
    .digest();
}
