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

import Signable from './signable'
import { default as NoteKeys } from './noteKeys'
import { default as NoteData } from './noteData'

/*
 * NoteInfo represents required note information that is signed before encrypting
 */
export default class NoteInfo extends Signable {
  constructor(data, noteKeys) {
    super()
    this.data = data
    this.noteKeys = noteKeys
  }

  serializable() {
    let toSerialize = {
      data: this.data,
      note_keys: this.noteKeys.serializable()
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
    let data = new NoteData(json.data)
    let noteKeys = NoteKeys.decode(json)
    var signableNote = new NoteInfo(data, noteKeys)
    return signableNote
  }

  /**
   * SignableSubsetFromNote creates extracts static note fields into a noteInfo
   * that will create the same signature if valid.
   */
  static signableSubsetFromNote(note) {
    return NoteInfo.decode(note.serializable())
  }
}
