/*!
 * Tozny e3db
 *
 * LICENSE
 *
 * Tozny dual licenses this product. For commercial use, please contact
 * info@tozny.com. For non-commercial use, the contents of this file are
 * subject to the TOZNY NON-COMMERCIAL LICENSE (the "License") which
 * permits use of the software only by government agencies, schools,
 * universities, non-profit organizations or individuals on projects that
 * do not receive external funding other than government research grants
 * and contracts.  Any other use requires a commercial license. You may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at https://tozny.com/legal/non-commercial-license.
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations under
 * the License. Portions of the software are Copyright (c) TOZNY LLC, 2018-19.
 * All rights reserved.
 *
 * @copyright Copyright (c) 2018-19 Tozny, LLC (https://tozny.com)
 */

'use strict'

/* eslint-disable no-unused-vars */

class Crypto {
  static __notImplemented(name) {
    throw new Error(`The method ${name} must be implemented in a subclass.`)
  }

  constructor() {
    if (this.constructor === Crypto) {
      throw new Error(
        'The Crypto class must be extended with a specific (Type)Crypto class before use.'
      )
    }
  }

  /**
   * Mode returns a string denoting which crypto library this implementation uses under the hood.
   */
  mode() {
    Crypto.__notImplemented('mode')
  }

  /**
   * EncryptField encrypts a string of text into a standard Tozny quat format using the provided access key.
   */
  encryptField(field, accessKey) {
    Crypto.__notImplemented('encryptField')
  }

  /**
   * DecryptField decrypts a standard Tozny quad using the provided access key.
   */
  decryptField(encryptedField, accessKey) {
    Crypto.__notImplemented('decryptField')
  }

  /**
   * EncryptNote implements method to encrypt the data within a note given the note and accessKey.
   */
  encryptNote(note, accessKey) {
    Crypto.__notImplemented('encryptNote')
  }

  /**
   * DecryptNote implements method to decrypt the data within a note given the note and accessKey.
   */
  decryptNote(encrypted, accessKey) {
    Crypto.__notImplemented('decryptNote')
  }

  /**
   * DecryptNoteEak is an internal method to decrypt a note's encrypted access key,
   * so that the note can be decrypted.
   */
  decryptNoteEak(readerKey, encryptedAk, writerKey) {
    Crypto.__notImplemented('decryptEak')
  }

  decryptEak(readerKey, encryptedEak) {
    Crypto.__notImplemented('decryptEak')
  }

  encryptAk(writerKey, ak, readerKey) {
    Crypto.__notImplemented('encryptAk')
  }

  decryptRecord(encrypted, accessKey) {
    Crypto.__notImplemented('decryptRecord')
  }

  encryptRecord(record, accessKey) {
    Crypto.__notImplemented('encryptRecord')
  }

  verifyDocumentSignature(document, signature, verifyingKey) {
    Crypto.__notImplemented('verifyDocumentSignature')
  }

  signDocument(document, signingKey) {
    Crypto.__notImplemented('signDocument')
  }

  b64encode(raw) {
    Crypto.__notImplemented('b64encode')
  }

  b64decode(encoded) {
    Crypto.__notImplemented('b64decode')
  }

  randomKey() {
    Crypto.__notImplemented('randomKey')
  }

  randomNonce() {
    Crypto.__notImplemented('randomNonce')
  }

  randomBytes(length) {
    Crypto.__notImplemented('randomBytes')
  }

  deriveKey(password, salt, length, iterations) {
    Crypto.__notImplemented('deriveKey')
  }

  deriveSigningKey(password, salt, iterations) {
    Crypto.__notImplemented('deriveSigningKey')
  }

  deriveCryptoKey(password, salt, iterations) {
    Crypto.__notImplemented('deriveCryptoKey')
  }

  deriveSymmetricKey(password, salt) {
    Crypto.__notImplemented('deriveSymmetricKey')
  }

  generateKeypair() {
    Crypto.__notImplemented('generateKeypair')
  }

  generateSigningKeypair() {
    Crypto.__notImplemented('generateSigningKeypair')
  }

  encryptLargeFile(fileObj, ak) {
    Crypto.__notImplemented('encryptLargeFile')
  }

  decryptFile(destinationFilename, ak, encryptedFile) {
    Crypto.__notImplemented('decryptFile')
  }

  /*
   * Sign a message and return the signature separate from the message.
   */
  signDetached(stringToSign, privateKey) {
    Crypto.__notImplemented('signDetached')
  }

  /*
   * Generate a secure hash with BLAKE2b.
   */
  genericHash(message) {
    Crypto.__notImplemented('genericHash')
  }
}

module.exports = Crypto
