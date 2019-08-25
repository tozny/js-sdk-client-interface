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
 * the License. Portions of the software are Copyright (c) TOZNY LLC, 2019.
 * All rights reserved.
 *
 * @copyright Copyright (c) 2019 Tozny, LLC (https://tozny.com)
 */

'use strict'

import { validateResponseAsJSON } from '../utils'
import AuthenticatedRequest from '../utils/authenticatedRequest'
import { AccountBillingStatus } from '../types'
import 'isomorphic-fetch'

export default class Client {
  constructor(config, storageClient, crypto) {
    // Construct this object.
    this.config = config
    this._storageClient = storageClient
    this._crypto = crypto
    this.authenticator = new AuthenticatedRequest(
      this._storageClient.config,
      this._crypto
    )
  }

  get crypto() {
    return this._crypto
  }

  get storageClient() {
    return this._storageClient
  }

  serialize() {
    return {
      config: JSON.stringify(this.config),
      storageConfig: JSON.stringify(this.storageClient.config)
    }
  }

  async getAccountBillingStatus() {
    let response = await this.authenticator.tokenFetch(
      this.config.apiUrl + '/v1/billing/subscription/status',
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    const rawResponse = await validateResponseAsJSON(response)
    const billingStatus = await AccountBillingStatus.decode(rawResponse)
    return billingStatus
  }
}
