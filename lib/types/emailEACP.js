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
 * NoteOptions represents optional values that are not required for creating a note,
 * but provide additional functionality. Some features are premium and require a TozStore client to work.
 */
export default class EmailEACP extends Serializable {
  static get jsonKey() {
    return 'email_otp'
  }

  constructor(email, template, providerLink) {
    super()
    this.emailAddress = email
    this.template = template
    this.provideLink = providerLink
  }

  serializable() {
    /* eslint-disable camelcase */
    let toSerialize = {
      email_address: this.emailAddress,
      template: this.template,
      provider_link: this.provideLink
    }
    /* eslint-enable */
    return toSerialize
  }

  static decode(json) {
    return new EmailEACP(json.email_address, json.template, json.provider_link)
  }
}
