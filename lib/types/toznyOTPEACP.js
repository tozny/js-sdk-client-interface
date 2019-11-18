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

/**
 * Configuration for an Tozny OTP based extended access control policy.
 */
export default class ToznyOTPEACP extends Serializable {
  /**
   * The key used to identify this EACP in a JSON object.
   *
   * @return {String} the EACP key.
   */
  static get jsonKey() {
    return 'tozny_otp_eacp'
  }

  /**
   * Configuration for an Tozny OTP EACP.
   *
   * @param {boolean} include A boolean to indicate that this EACP should be included
   */
  constructor(include) {
    super()
    this.include = include

  }

  /**
   * Create a plain object representation of the Tozny OTP EACP. Used for JSON serialization.
   *
   * @return {Object} A plain JS object representing the Tozny OTP EACP configuration.
   */
  serializable() {
    /* eslint-disable camelcase */
    let toSerialize = {
      include: this.include,
    }
    /* eslint-enable */
    return toSerialize
  }

  /**
   * Create a new ToznyOTPEACP instance from a Javascript object.
   *
   * @param {Object} json A plain JS object containing the needed EmailEACP configuration.
   *
   * @return {ToznyOTPEACP} The constructed EmailEACP object based on the passed JS object.
   */
  static decode(json) {
    return new ToznyOTPEACP(json.include)
  }
}
