const createHmac = require('create-hmac');

export function hmacSHA512(key: Buffer, data: Buffer[]): Buffer {
  const hmac = createHmac('sha512', key);
  data.forEach(d => hmac.update(d));
  return hmac.digest();
}

export function hmacSHA256(key: Buffer, data: Buffer[]): Buffer {
  const hmac = createHmac('sha256', key);
  data.forEach(d => hmac.update(d));
  return hmac.digest();
}
