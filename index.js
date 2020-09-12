const hash = require('hash.js');
const randomBytes = require('randombytes');

const KEY_SIG_ENTRY_COUNT = 256;

class SimpleLamport {
  constructor(options) {
    options = options || {};
    this.keyFormat = options.keyFormat || 'base64';
    this.signatureFormat = options.signatureFormat || 'base64';
    this.hashEncoding = options.hashEncoding || 'base64';
    this.hashElementByteSize = options.hashElementByteSize || 32;
    this.seedEncoding = options.seedEncoding || 'hex';
    this.seedByteSize = options.seedByteSize || 64;
    if (options.hashFunction) {
      this.hash = options.hashFunction;
    } else {
      this.hash = this.sha256;
    }

    if (this.keyFormat === 'object') {
      this.encodeKey = (rawKey) => {
        return rawKey;
      };
      this.decodeKey = (encodedkey) => {
        return encodedkey;
      };
    } else if (this.keyFormat === 'json') {
      this.encodeKey = (rawKey) => {
        return JSON.stringify(rawKey);
      };
      this.decodeKey = (encodedKey) => {
        return JSON.parse(encodedKey);
      };
    } else if (this.keyFormat === 'buffer') {
      this.encodeKey = (rawKey) => {
        return this._encodeKeyToBuffer(rawKey);
      };
      this.decodeKey = (encodedKey) => {
        return this._decodeKeyFromBuffer(encodedKey);
      };
    } else {
      this.encodeKey = (rawKey) => {
        return this._encodeKeyToBuffer(rawKey).toString(this.keyFormat);
      };
      this.decodeKey = (encodedKey) => {
        let keyBuffer = Buffer.from(encodedKey, this.keyFormat);
        return this._decodeKeyFromBuffer(keyBuffer);
      };
    }

    if (this.signatureFormat === 'object') {
      this.encodeSignature = (rawSignature) => {
        return rawSignature;
      };
      this.decodeSignature = (encodedSignature) => {
        return encodedSignature;
      };
    } else if (this.signatureFormat === 'json') {
      this.encodeSignature = (rawSignature) => {
        return JSON.stringify(rawSignature);
      };
      this.decodeSignature = (encodedSignature) => {
        return JSON.parse(encodedSignature);
      };
    } else if (this.signatureFormat === 'buffer') {
      this.encodeSignature = (rawSignature) => {
        return this._encodeSignatureToBuffer(rawSignature);
      };
      this.decodeSignature = (encodedSignature) => {
        return this._decodeSignatureFromBuffer(encodedSignature);
      };
    } else {
      this.encodeSignature = (rawSignature) => {
        return this._encodeSignatureToBuffer(rawSignature).toString(this.signatureFormat);
      };
      this.decodeSignature = (encodedSignature) => {
        let signatureBuffer = Buffer.from(encodedSignature, this.signatureFormat);
        return this._decodeSignatureFromBuffer(signatureBuffer);
      };
    }
  }

  generateSeed() {
    return randomBytes(this.seedByteSize).toString(this.seedEncoding);
  }

  generateKeysFromSeed(seed, index) {
    if (index == null) {
      index = 0;
    }
    let privateKey = [
      this.generateRandomArrayFromSeed(KEY_SIG_ENTRY_COUNT, `${seed}-${index}-a`),
      this.generateRandomArrayFromSeed(KEY_SIG_ENTRY_COUNT, `${seed}-${index}-b`)
    ];

    let publicKey = privateKey.map((privateKeyPart) => {
      return privateKeyPart.map((encodedString) => this.hash(encodedString, this.hashEncoding));
    });

    return {
      privateKey: this.encodeKey(privateKey),
      publicKey: this.encodeKey(publicKey)
    };
  }

  generateKeys() {
    let privateKey = [
      this.generateRandomArray(KEY_SIG_ENTRY_COUNT, this.hashElementByteSize),
      this.generateRandomArray(KEY_SIG_ENTRY_COUNT, this.hashElementByteSize)
    ];

    let publicKey = privateKey.map((privateKeyPart) => {
      return privateKeyPart.map((encodedString) => this.hash(encodedString, this.hashEncoding));
    });

    return {
      privateKey: this.encodeKey(privateKey),
      publicKey: this.encodeKey(publicKey)
    };
  }

  sign(message, privateKey) {
    let privateKeyRaw = this.decodeKey(privateKey);
    let messageHash = this.sha256(message, this.hashEncoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);
    let signature = messageBitArray.map((bit, index) => privateKeyRaw[bit][index]);

    return this.encodeSignature(signature);
  }

  verify(message, signature, publicKey) {
    let signatureRaw;
    let publicKeyRaw;
    try {
      signatureRaw = this.decodeSignature(signature);
      publicKeyRaw = this.decodeKey(publicKey);
    } catch (error) {
      return false;
    }
    let messageHash = this.sha256(message, this.hashEncoding);
    let messageBitArray = this.convertEncodedStringToBitArray(messageHash);

    return messageBitArray.every((bit, index) => {
      let signatureItemHash = this.hash(signatureRaw[index], this.hashEncoding);
      let targetPublicKeyItem = publicKeyRaw[bit][index];
      return signatureItemHash === targetPublicKeyItem;
    });
  }

  sha256(message, encoding) {
    let shasum = hash.sha256().update(message).digest('hex');
    if (encoding === 'hex') {
      return shasum;
    }
    return Buffer.from(shasum, 'hex').toString(encoding || 'base64');
  }

  generateRandomArray(length, elementBytes) {
    let randomArray = [];
    for (let i = 0; i < length; i++) {
      randomArray.push(randomBytes(elementBytes).toString(this.hashEncoding));
    }
    return randomArray;
  }

  generateRandomArrayFromSeed(length, seed) {
    let randomArray = [];
    for (let i = 0; i < length; i++) {
      randomArray.push(this.hash(`${seed}-${i}`).toString(this.hashEncoding));
    }
    return randomArray;
  }

  convertEncodedStringToBitArray(encodedString) {
    let buffer = Buffer.from(encodedString, this.hashEncoding);

    let bitArray = [];
    for (let byte of buffer) {
      for (let i = 0; i < 8; i++) {
        bitArray.push(byte >> (7 - i) & 1);
      }
    }
    return bitArray;
  }

  _encodeKeyToBuffer(rawKey) {
    let bufferArray = [];
    for (let keyPart of rawKey) {
      for (let item of keyPart) {
        bufferArray.push(Buffer.from(item, this.hashEncoding));
      }
    }
    return Buffer.concat(bufferArray);
  }

  _decodeKeyFromBuffer(encodedKey) {
    let keyFirstPart = [];
    let keySecondPart = [];
    let key = [keyFirstPart, keySecondPart];
    for (let i = 0; i < KEY_SIG_ENTRY_COUNT; i++) {
      let byteOffset = i * this.hashElementByteSize;
      let bufferItem = encodedKey.slice(byteOffset, byteOffset + this.hashElementByteSize);
      keyFirstPart.push(bufferItem.toString(this.hashEncoding));
    }
    let totalKeyLength = KEY_SIG_ENTRY_COUNT * 2;
    for (let i = KEY_SIG_ENTRY_COUNT; i < totalKeyLength; i++) {
      let byteOffset = i * this.hashElementByteSize;
      let bufferItem = encodedKey.slice(byteOffset, byteOffset + this.hashElementByteSize);
      keySecondPart.push(bufferItem.toString(this.hashEncoding));
    }
    return key;
  }

  _encodeSignatureToBuffer(rawSignature) {
    let bufferArray = [];
    for (let item of rawSignature) {
      bufferArray.push(Buffer.from(item, this.hashEncoding));
    }
    return Buffer.concat(bufferArray);
  }

  _decodeSignatureFromBuffer(encodedSignature) {
    let signatureArray = [];
    for (let i = 0; i < KEY_SIG_ENTRY_COUNT; i++) {
      let byteOffset = i * this.hashElementByteSize;
      let bufferItem = encodedSignature.slice(byteOffset, byteOffset + this.hashElementByteSize);
      signatureArray.push(bufferItem.toString(this.hashEncoding));
    }
    return signatureArray;
  }
}

module.exports = SimpleLamport;
