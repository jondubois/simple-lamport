const crypto = require('crypto');

module.exports = function (secret, secretEncoding, message, outputEncoding) {
  return crypto.createHmac('sha256', Buffer.from(secret, secretEncoding))
    .update(message)
    .digest(outputEncoding || 'base64');
};
