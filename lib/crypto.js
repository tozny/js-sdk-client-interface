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

class Crypto {
  __notImplemented(name) {
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
    this.__notImplemented('mode')
  }

  /**
   * EncryptNote implements method to encrypt the data within a note given the note and accessKey.
   */
  encryptNote() {
    this.__notImplemented('encryptNote')
  }

  /**
   * DecryptNote implements method to decrypt the data within a note given the note and accessKey.
   */
  decryptNote() {
    this.__notImplemented('decryptNote')
  }

  /**
   * DecryptNoteEak is an internal method to decrypt a note's encrypted access key,
   * so that the note can be decrypted.
   */
  decryptNoteEak() {
    this.__notImplemented('decryptEak')
  }

  decryptEak() {
    this.__notImplemented('decryptEak')
  }

  encryptAk() {
    this.__notImplemented('encryptAk')
  }

  decryptRecord() {
    this.__notImplemented('decryptRecord')
  }

  encryptRecord() {
    this.__notImplemented('encryptRecord')
  }

  verifyDocumentSignature() {
    this.__notImplemented('verifyDocumentSignature')
  }

  signDocument() {
    this.__notImplemented('signDocument')
  }

  b64encode() {
    this.__notImplemented('b64encode')
  }

  b64decode() {
    this.__notImplemented('b64decode')
  }

  randomKey() {
    this.__notImplemented('randomKey')
  }

  deriveKey() {
    this.__notImplemented('deriveKey')
  }

  deriveSigningKey() {
    this.__notImplemented('deriveSigningKey')
  }

  deriveCryptoKey() {
    this.__notImplemented('deriveCryptoKey')
  }

  deriveSymmetricKey() {
    this.__notImplemented('deriveSymmetricKey')
  }

  generateKeypair() {
    this.__notImplemented('generateKeypair')
  }

  generateSigningKeypair() {
    this.__notImplemented('generateSigningKeypair')
  }

  /*
   * Sign a message and return the signature separate from the message.
   */
  signDetached() {
    this.__notImplemented('signDetached')
  }

  /*
   * Generate a secure hash with BLAKE2b.
   */
  genericHash() {
    this.__notImplemented('genericHash')
  }
}

module.exports = Crypto
