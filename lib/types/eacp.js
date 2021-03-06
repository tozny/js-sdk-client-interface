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
import LastAccessEACP from './lastAccessEACP'
import ToznyOTPEACP from './toznyOTPEACP'

/**
 * EACP defines the various extended access control policies on data object.
 *
 * The EACP types are hard coded, and each data object can have one of each
 * kind. These are defined in sub objects. The EACP object is to mix all of the
 * various kinds together so they can be sent to the server to apply the policy.
 */
export default class EACP extends Serializable {
  /**
   * Create an EACP instance to organize extended access control policies for data objects.
   *
   * @param {EmailEACP} emailEACP An Email EACP configuration to associate with the data object.
   * @param {LastAccessEACP} noteAccessEACP A Last Access EACP configuration to associate with the object.
   * @param {ToznyOTPEACP} toznyOTPEACP A Tozny OTP EACP configuration to associate with the object.
   */
  constructor(emailEACP, noteAccessEACP, toznyOTPEACP) {
    super()

    if (emailEACP instanceof EmailEACP) {
      this.emailEACP = emailEACP
    }
    if (noteAccessEACP instanceof LastAccessEACP) {
      this.noteAccessEACP = noteAccessEACP
    }
    if (toznyOTPEACP instanceof ToznyOTPEACP) {
      this.toznyOTPEACP = toznyOTPEACP
    }
  }

  /**
   * Create a plain object representation of the EACP. Used for JSON serialization.
   *
   * @return {Object} A plain JS object representing the EACP.
   */
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

  /**
   * Create a new EACP instance from a Javascript object.
   *
   * @param {Object} json A plain JS object containing the needed EACP fields.
   *
   * @return {EACP} The constructed EACP object based on the passed JS object.
   */
  static decode(json) {
    let emailEACP
    let noteAccessEACP
    let toznyOTPEACP
    if (typeof json[EmailEACP.jsonKey] === 'object') {
      emailEACP = EmailEACP.decode(json[EmailEACP.jsonKey])
    }
    if (typeof json[LastAccessEACP.jsonKey] === 'object') {
      noteAccessEACP = LastAccessEACP.decode(json[LastAccessEACP.jsonKey])
    }
    if (typeof json[ToznyOTPEACP.jsonKey] === 'object') {
      toznyOTPEACP = ToznyOTPEACP.decode(json[ToznyOTPEACP.jsonKey])
    }
    return new EACP(emailEACP, noteAccessEACP, toznyOTPEACP)
  }
}
