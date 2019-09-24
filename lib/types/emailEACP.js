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
 * Configuration for an email based extended access control policy.
 */
export default class EmailEACP extends Serializable {
  /**
   * The key used to identify this EACP in a JSON object.
   *
   * @return {String} the EACP key.
   */
  static get jsonKey() {
    return 'email_eacp'
  }

  /**
   * Configuration for an email based OTP EACP.
   *
   * @param {string} email The email address to send the otp challenge to.
   * @param {string} template The notification service email template to use when sending the challenge.
   * @param {string} providerLink The URL of the endpoint that will handle the challenge when linked to in the email.
   */
  constructor(email, template, providerLink) {
    super()
    this.emailAddress = email
    this.template = template
    this.provideLink = providerLink
  }

  /**
   * Create a plain object representation of the email EACP. Used for JSON serialization.
   *
   * @return {Object} A plain JS object representing the email EACP configuration.
   */
  serializable() {
    /* eslint-disable camelcase */
    let toSerialize = {
      email_address: this.emailAddress,
      template: this.template,
      provider_link: this.provideLink,
    }
    /* eslint-enable */
    return toSerialize
  }

  /**
   * Create a new EmailEACP instance from a Javascript object.
   *
   * @param {Object} json A plain JS object containing the needed EmailEACP configuration.
   *
   * @return {EmailEACP} The constructed EmailEACP object based on the passed JS object.
   */
  static decode(json) {
    return new EmailEACP(json.email_address, json.template, json.provider_link)
  }
}
