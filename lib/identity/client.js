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

import { checkStatus, urlEncodeData } from '../utils'
import 'isomorphic-fetch'

async function fetchToken(client) {
  /* eslint-disable camelcase */
  const bodyData = {
    grant_type: 'password',
    client_id: 'admin-cli'
  }
  /* eslint-enable */

  const request = await client.storageClient.authenticator.tsv1Fetch(
    client.config.apiUrl +
      `/auth/realms/${client.config.realmName}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: urlEncodeData(bodyData)
    }
  )
  const response = await checkStatus(request)
  return response.json()
}

export default class Client {
  constructor(config, storageClient, crypto) {
    // Construct this object.
    this.config = config
    this._storageClient = storageClient
    this._crypto = crypto
    this._tokenInfo = false
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

  async token() {
    const info = await this.tokenInfo
    return info.access_token
  }

  async tokenInfo() {
    const fiveFromNow = Math.floor(Date.now() / 1000) + 5 * 60
    if (!this._tokenInfo || this._tokenInfo.expires < fiveFromNow) {
      const tokenInfo = await fetchToken(this)
      this._tokenInfo = tokenInfo
    }
    return this._tokenInfo
  }

  async fetch(url, options) {
    const token = await this.token()
    options.headers = options.headers || {}
    options.headers.Authorization = `Bearer ${token}`
    return fetch(url, options)
  }
}
