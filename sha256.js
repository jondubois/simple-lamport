const crypto = require('crypto');

module.exports = function (message, encoding) {
  return crypto.createHash('sha256').update(message, 'utf8').digest(encoding || 'base64');
};
