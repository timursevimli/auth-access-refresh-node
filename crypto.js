'use strict';

const crypto = require('node:crypto');

const CRC_LEN = 4;

const generateKey = (possible, length) => {
  if (length < 0) return '';
  const base = possible.length;
  if (base < 1) return '';
  const key = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    const index = crypto.randomInt(0, base);
    key[i] = possible.charCodeAt(index);
  }
  return String.fromCharCode.apply(null, key);
};

const crcToken = (secret, key) => {
  const md5 = crypto.createHash('md5').update(key + secret);
  return md5.digest('hex').substring(0, CRC_LEN);
};

const TOKEN_LENGTH = 180;
const ALPHA_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ALPHA_LOWER = 'abcdefghijklmnopqrstuvwxyz';
const ALPHA = ALPHA_UPPER + ALPHA_LOWER;
const DIGIT = '0123456789';
const ALPHA_DIGIT = ALPHA + DIGIT;

const generateToken = (
  secret,
  characters = ALPHA_DIGIT,
  length = TOKEN_LENGTH,
) => {
  if (length < CRC_LEN || secret === '' || characters === '') return '';
  const key = generateKey(characters, length - CRC_LEN);
  return key + crcToken(secret, key);
};

module.exports = {
  generateToken,
};
