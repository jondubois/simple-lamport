const hash = require('hash.js');

module.exports = function (message, encoding) {
  let shasum = hash.sha256().update(message).digest('hex');
  if (encoding === 'hex') {
    return shasum;
  }
  return Buffer.from(shasum, 'hex').toString(encoding || 'base64');
};
