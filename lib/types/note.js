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

import { default as CoreNote } from './coreNote'
import { default as NoteOptions } from './noteOptions'

export default class Note {
  constructor(coreNote, signature, options) {
    // Required values
    this.core = coreNote
    this.signature = signature
    // Optional values
    this.options = options
    this.createdAt = null // Server defined value, not available until creation.
    this.noteId = null
  }

  toJson() {
    return JSON.stringify({
      mode: this.core.mode,
      recipient_signing_key: this.core.recipientSigningKey,
      writer_signing_key: this.core.writerSigningKey,
      writer_encryption_key: this.core.writerEncryptionKey,
      encrypted_access_key: this.core.encryptedAccessKey,
      type: this.core.type,
      data: this.core.data,
      plain: this.core.plain,
      file_meta: this.core.fileMeta,
      signature: this.signature,
      max_views: this.options.maxViews,
      client_id: this.options.clientId,
      id_string: this.options.idString,
      expiration: this.options.expiration,
      created_at: this.createdAt
    })
  }

  static decode(json) {
    let coreNote = CoreNote.decode(json)
    let options = NoteOptions.decode(json)
    let signature = json.signature === undefined ? null : json.signature
    var note = new Note(coreNote, signature, options)

    // Server defined values
    let createdAt = json.created_at === null ? null : json.created_at
    let noteId = json.note_id === null ? null : json.note_id
    note.createdAt = createdAt
    note.noteId = noteId
    return note
  }

  static clone(note) {
    let cloneCore = CoreNote.decode(note.core.serializable())
    let cloneOptions = NoteOptions.decode(note.options.serializable())
    let cloneNote = new Note(cloneCore, note.signature, cloneOptions)
    cloneNote.createdAt = note.createdAt
    cloneNote.noteId = note.noteId
    return cloneNote
  }
}
