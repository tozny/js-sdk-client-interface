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

import fetch from 'isomorphic-fetch'
import { checkStatus } from './utils'
import CryptoConsumer from './utils/crytoConsumer'
import Client from './client'

export default class Identity extends CryptoConsumer {
  // Static login(username, password, apiUrl) {
  //   // Use all of things to fetch the note and log in.
  //   return apiUrl
  // }

  constructor(apiUrl, realmID, realmName) {
    super()
    this.apiUrl = apiUrl
    this.realmID = realmID
    this.realmName = realmName
  }

  async register(username, password, token) {
    const cryptoKeys = await Client.generateKeypair()
    const signingKeys = await Client.generateSigningKeypair()
    /* eslint-disable camelcase */
    const body = {
      realm_registration_token: token,
      realm_id: this.realmID,
      identity: {
        realm_id: this.realmID,
        name: username,
        public_key: {
          curve25519: cryptoKeys.public_key
        },
        signing_key: {
          ed25519: signingKeys.public_key
        }
      }
    }
    /* eslint-enable */
    const regResponse = await fetch(this.apiUrl, {
      body
    })
    await checkStatus(regResponse)
    return true
  }
}
