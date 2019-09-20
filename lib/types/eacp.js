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
import EmailEACP from './emailEACP'
import NoteAccessEACP from './noteAccessEACP'

/**
 * NoteOptions represents optional values that are not required for creating a note,
 * but provide additional functionality. Some features are premium and require a TozStore client to work.
 */
export default class EACP extends Serializable {
  constructor(emailEACP, noteAccessEACP) {
    super()

    if (emailEACP instanceof EmailEACP) {
      this.emailEACP = emailEACP
    }
    if (noteAccessEACP instanceof noteAccessEACP) {
      this.noteAccessEACP = noteAccessEACP
    }
  }

  serializable() {
    let toSerialize = {}
    // Ensure that plainMeta is always an object, even it it's set to null
    for (let eacp in this) {
      if (!this.hasOwnProperty(eacp)) {
        continue
      }
      toSerialize[this[eacp].constructor.jsonKey] = this[eacp].serializable()
    }
    return toSerialize
  }

  static decode(json) {
    let emailEACP
    let noteAccessEACP
    if (typeof json[EmailEACP.jsonKey] === 'object') {
      emailEACP = EmailEACP.decode(json[EmailEACP.jsonKey])
    }
    if (typeof json[NoteAccessEACP.jsonKey] === 'object') {
      noteAccessEACP = NoteAccessEACP.decode(json[NoteAccessEACP.jsonKey])
    }
    return new EACP(emailEACP, noteAccessEACP)
  }
}
