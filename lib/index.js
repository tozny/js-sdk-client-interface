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

import Identity from './identity'
import Billing from './billing'
import * as Storage from './storage'
import * as types from './types'
import Crypto from './crypto'

export { Billing, Identity, Storage, Crypto, types }

export default class Tozny {
  constructor(billing, identity, storage, crypto, helpers = {}) {
    if (
      Billing.isExtension(billing) &&
      Identity.isExtension(identity) &&
      Storage.isExtension(storage) &&
      Crypto.isExtension(crypto)
    ) {
      this.Billing = billing
      this.Identity = identity
      this.Storage = storage
      this.Crypto = crypto
      this.crypto = crypto.instance
      this.helpers = helpers
      this.types = types
    } else {
      throw new Error(
        'To create a Tozny object you must pass valid implementations of the Billing, Storage, Identity, and Crypto interfaces.'
      )
    }
  }
}
