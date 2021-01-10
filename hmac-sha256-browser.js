const hash = require('hash.js');

module.exports = function (secret, secretEncoding, message, outputEncoding) {
  let shasum = hash.hmac(hash.sha256, Buffer.from(secret, secretEncoding))
    .update(message)
    .digest('hex');
  if (outputEncoding === 'hex') {
    return shasum;
  }
  return Buffer.from(shasum, 'hex').toString(outputEncoding || 'base64');
};
