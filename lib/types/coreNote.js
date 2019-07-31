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

/*
 * CoreNote represents required note information that is signed before encrypting
 */
export default class CoreNote extends Serializable {
  constructor(
    type,
    data,
    plainMeta,
    fileMeta = null,
    mode,
    recipientSigningKey,
    writerSigningKey,
    writerEncryptionKey,
    encryptedAccessKey
  ) {
    super()
    // Required values
    this.type = type
    this.data = data
    this.plainMeta = plainMeta
    this.fileMeta = fileMeta
    // Required crypto params
    this.mode = mode
    this.recipientSigningKey = recipientSigningKey
    this.writerSigningKey = writerSigningKey
    this.writerEncryptionKey = writerEncryptionKey
    this.encryptedAccessKey = encryptedAccessKey
  }

  serializable() {
    let toSerialize = {
      type: this.type,
      data: this.data,
      mode: this.mode,
      recipient_signing_key: this.recipientSigningKey,
      writer_signing_key: this.writerSigningKey,
      writer_encryption_key: this.writerEncryptionKey,
      encrypted_access_key: this.encryptedAccessKey
    }

    // Ensure that plainMeta is always an object, even it it's set to null
    if (this.plain_meta === null) {
      toSerialize.plain_meta = {}
    } else {
      toSerialize.plain_meta = this.plain_meta
    }

    // Ensure that fileMeta is always an object, even it it's set to null
    if (this.plain_meta === null) {
      toSerialize.file_meta = {}
    } else {
      toSerialize.file_meta = this.file_meta
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
    let type = json.type === undefined ? null : json.type
    let data = json.data === undefined ? {} : json.data
    let plainMeta = json.plain_meta === undefined ? {} : json.plain_meta
    let fileMeta = json.file_meta === undefined ? {} : json.file_meta
    let mode = json.mode === undefined ? null : json.mode
    let recipientSigningKey =
      json.recipient_signing_key === undefined ? null : json.recipient_signing_key
    let writerSigningKey =
      json.writer_signing_key === undefined ? null : json.writer_signing_key
    let writerEncryptionKey =
      json.writer_encryption_key === undefined ? null : json.writer_encryption_key
    let encryptedAccessKey =
      json.encrypted_access_key === undefined ? null : json.encrypted_access_key
    return new CoreNote(
      type,
      data,
      plainMeta,
      fileMeta,
      mode,
      recipientSigningKey,
      writerSigningKey,
      writerEncryptionKey,
      encryptedAccessKey
    )
  }
}
