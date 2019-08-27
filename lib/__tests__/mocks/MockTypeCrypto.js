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

import 'es6-promise/auto'
import { default as Crypto } from '../../crypto'
import { default as KeyPair } from '../../types/keyPair'
import { default as Meta } from '../../types/meta'
import { default as Record } from '../../types/record'
import { default as RecordData } from '../../types/recordData'

/* eslint-disable no-unused-vars */
export default class MockTypeCrypto extends Crypto {
  async decryptEak(readerKey, encryptedAk) {
    return new Promise(resolve => {
      resolve(`${readerKey}.AccessKey`)
    })
  }

  async encryptAk(writerKey, ak, readerKey) {
    return new Promise(resolve => {
      resolve(`${writerKey}.Encrypted${ak}.${readerKey}`)
    })
  }

  async decryptRecord(encrypted, accessKey) {
    return new Record(
      new Meta('bogusWriterId', 'bogusUserId', 'bogusType', { plain: 'bogus' }),
      new RecordData({ recordData: 'decryptedData' }),
      encrypted.signature
    )
  }

  async encryptRecord(record, accessKey) {
    return new Record(
      new Meta('bogusWriterId', 'bogusUserId', 'bogusType', { plain: 'bogus' }),
      new RecordData({ recordData: 'encryptedData' }),
      record.signature
    )
  }

  async verifyDocumentSignature(document, signature, verifyingKey) {
    console.log('[mocked verifyDocumentSignature] - ', document)
    return new Promise(resolve => {
      resolve(true)
    })
  }

  async signDocument(document, signingKey) {
    console.log('[mocked signDocument] - ', document)
    return new Promise(resolve => {
      resolve(`${signingKey}.signature`)
    })
  }

  async b64encode(raw) {
    return 'b64encodeRaw'
  }

  async b64decode(encoded) {
    return 'b64encodeEncoded'
  }

  async randomKey() {
    return 'returnedRandomKey'
  }

  async deriveKey(password, salt, length) {
    return new Promise((resolve, reject) => {
      resolve(null)
    })
  }

  async deriveSigningKey(password, salt) {
    return new KeyPair('publicSignKey', 'privateSignKey')
  }

  async deriveCryptoKey(password, salt) {
    return new KeyPair('publicKey', 'privateKey')
  }

  async deriveSymmetricKey(password, salt) {
    return `${password}.${salt}`
  }

  async generateKeypair() {
    return new KeyPair('publicKey', 'privateKey')
  }

  async generateSigningKeypair() {
    return new KeyPair('publicSignKey', 'privateSignKey')
  }
}

/* eslint-enable no-unused-vars */
