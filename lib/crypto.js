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
   * EncryptNote implements method to encrypt the data within a note given the note and accessKey.
   */
  encryptNote() {
    Crypto.__notImplemented('encryptNote')
  }

  /**
   * DecryptNote implements method to decrypt the data within a note given the note and accessKey.
   */
  decryptNote() {
    Crypto.__notImplemented('decryptNote')
  }

  /**
   * DecryptNoteEak is an internal method to decrypt a note's encrypted access key,
   * so that the note can be decrypted.
   */
  decryptNoteEak() {
    Crypto.__notImplemented('decryptEak')
  }

  decryptEak() {
    Crypto.__notImplemented('decryptEak')
  }

  encryptAk() {
    Crypto.__notImplemented('encryptAk')
  }

  decryptRecord() {
    Crypto.__notImplemented('decryptRecord')
  }

  encryptRecord() {
    Crypto.__notImplemented('encryptRecord')
  }

  verifyDocumentSignature() {
    Crypto.__notImplemented('verifyDocumentSignature')
  }

  signDocument() {
    Crypto.__notImplemented('signDocument')
  }

  b64encode() {
    Crypto.__notImplemented('b64encode')
  }

  b64decode() {
    Crypto.__notImplemented('b64decode')
  }

  randomKey() {
    Crypto.__notImplemented('randomKey')
  }

  deriveKey() {
    Crypto.__notImplemented('deriveKey')
  }

  deriveSigningKey() {
    Crypto.__notImplemented('deriveSigningKey')
  }

  deriveCryptoKey() {
    Crypto.__notImplemented('deriveCryptoKey')
  }

  deriveSymmetricKey() {
    Crypto.__notImplemented('deriveSymmetricKey')
  }

  generateKeypair() {
    Crypto.__notImplemented('generateKeypair')
  }

  generateSigningKeypair() {
    Crypto.__notImplemented('generateSigningKeypair')
  }

  encryptLargeFile() {
    Crypto.__notImplemented('encryptLargeFile')
  }

  decryptFile() {
    Crypto.__notImplemented('decryptFile')
  }

  /*
   * Sign a message and return the signature separate from the message.
   */
  signDetached() {
    Crypto.__notImplemented('signDetached')
  }

  /*
   * Generate a secure hash with BLAKE2b.
   */
  genericHash() {
    Crypto.__notImplemented('genericHash')
  }
}

module.exports = Crypto
