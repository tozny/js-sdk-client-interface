/*!
 * Tozny e3db
 *
 * LICENSE
 *
 * Tozny dual licenses this product. For commercial use, please contact
 * info@tozny.com. For non-commercial use, this license permits use of the
 * software only by government agencies, schools, universities, non-profit
 * organizations or individuals on projects that do not receive external
 * funding other than government research grants and contracts. Any other use
 * requires a commercial license. For the full license, please see LICENSE.md,
 * in this source repository.
 *
 * @copyright Copyright (c) 2018-19 Tozny, LLC (https://tozny.com)
 */

'use strict'

import Serializable from './serializable'
import { write } from 'fs'

export default class NoteKeys extends Serializable {
  constructor(
    mode,
    recipientSigningKey,
    writerSigningKey,
    writerEncryptionKey,
    encryptedAccessKey
  ) {
    super()
    this.mode = mode
    this.recipientSigningKey = recipientSigningKey
    this.writerSigningKey = writerSigningKey
    this.writerEncryptionKey = writerEncryptionKey
    this.encryptedAccessKey = encryptedAccessKey
  }

  serializable() {
    let toSerialize = {
      mode: this.mode,
      recipient_signing_key: this.recipientSigningKey,
      writer_signing_key: this.writerSigningKey,
      writer_encryption_key: this.writerEncryptionKey,
      encrypted_access_key: this.encryptedAccessKey
    }

    const serializedKeys = Object.keys(toSerialize)
    for (const key of serializedKeys) {
      if (toSerialize[key] === null) {
        delete toSerialize[key]
      }
    }
    return toSerialize
  }

  static decode(json) {
    let mode = json.mode === undefined ? null : json.mode
    let recipientSigningKey =
      json.recipient_signing_key === undefined ? null : json.recipient_signing_key
    let writerSigningKey =
      json.writer_signing_key === undefined ? null : json.writer_signing_key
    let writerEncryptionKey =
      json.writer_encryption_key === undefined ? null : json.writer_encryption_key
    let encryptedAccessKey =
      json.encrypted_access_key === undefined ? null : json.encrypted_access_key
    return new NoteKeys(
      mode,
      recipientSigningKey,
      writerSigningKey,
      writerEncryptionKey,
      encryptedAccessKey
    )
  }
}
