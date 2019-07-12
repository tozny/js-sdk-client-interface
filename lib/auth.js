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
 * the License. Portions of the software are Copyright (c) TOZNY LLC, 2017.
 * All rights reserved.
 *
 * @copyright Copyright (c) 2017 Tozny, LLC (https://tozny.com)
 */

/* global fetch */

import 'isomorphic-fetch'

import { default as uuid } from 'uuid/v4'

const supportedTSV1Algorithms = ['TSV1-ED25519-BLAKE2B']

/**
 * Fallback polyfill to allow for HTTP Basic authentication from either Node
 * or browser-based JavaScript.
 *
 * @param {string} str String to encode as Base64
 */
function btoa(str) {
  let buf = Buffer.from(str, 'utf8')
  return buf.toString('base64')
}

function sortQueryParams(queryString) {
  // Parse query string into field=values
  var query = queryString.split('&')
  for (var i = 0; i < query.length; i++) {
    // Separate fields from values
    let splitQuery = query[i].split('=')
    query[i] = splitQuery
  }
  // Sort alphabetically
  query.sort(function(a, b) {
    return a[0] < b[0] ? -1 : 1
  })
  // Reconstruct query
  for (var j = 0; j < query.length; j++) {
    query[j] = query[j].join('=')
  }
  return query.join('&')
}

class Auth {
  constructor(apiKeyId, apiSecret, publicSigningKey, privateSigningKey, crypto, apiUrl) {
    this.apiKeyId = apiKeyId
    this.apiSecret = apiSecret
    this.publicSigningKey = publicSigningKey
    this.privateSigningKey = privateSigningKey
    this.apiUrl = apiUrl
    this.crypto = crypto
    this._authToken = null
    this._authTokenTimeout = 0 // Minimum UNIX timestamp
  }

  /**
   * Wrapper method to generate the Authentication header through tsv1 if possible, but defaults to oauth if tsv1 is missing signing keys
   * Throws if both methods of authentication are not possible
   *
   * @param {string} urlString Absolute URL to fetch from the server
   * @param {object} options Object representing additional settings for the fetch
   *
   * @returns {Promise<string>} Promise of a valid authentication header
   */
  async authenticate(urlString, options) {
    if (this.canPerformTSV1Auth(urlString, options)) {
      return this.tsv1Auth(urlString, options)
    }
    if (this.canPerformTokenAuth()) {
      return this.tokenAuth()
    }
    throw new Error(
      'This client is missing the keys to perform any supported authentication method'
    )
  }

  canPerformTSV1Auth(urlString, options) {
    return (
      !(this.publicSigningKey === undefined) &&
      !(this.privateSigningKey === undefined) &&
      !(urlString === undefined) &&
      !(options === undefined)
    )
  }

  /**
   * Wrapper method to generate the Authentication header using tsv1
   * Throws if tsv1 is missing needed signing keys or url options
   *
   * @param {string} urlString Absolute URL to fetch from the server
   * @param {object} options Object representing additional settings for the fetch
   *
   * @returns {Promise<string>} Promise of a valid authentication header
   */
  async getTSV1Header(urlString, options, userID) {
    if (this.canPerformTSV1Auth(urlString, options)) {
      return this.tsv1Auth(urlString, options, userID)
    }
    throw new Error('Missing public or private signing key')
  }

  /**
   * Generates and a signed request header according to the tsv1 specifications
   *
   * @returns {Promise<string>} Promise of a valid authentication header
   */
  async tsv1Auth(urlString, options, userID = '') {
    // Currently requires trailing slash
    const url = new URL(urlString)
    const path = url.pathname
    var queryString = url.search.substr(1)
    queryString = sortQueryParams(queryString)
    const timestamp = (Date.now() / 1000) | 0
    // Only one sodium cipher is currently supported.
    const authMethod = supportedTSV1Algorithms[0]
    const nonce = uuid()
    const privateSigningKeyBytes = await this.crypto.b64decode(this.privateSigningKey)
    const headerString = `${authMethod}; ${
      this.publicSigningKey
    }; ${timestamp}; ${nonce}; uid:${userID}`
    const strToSign = `${path}; ${queryString}; ${options.method}; ${headerString}`
    const hashToSign = await this.crypto.genericHash(strToSign)
    const fullSigRaw = this.crypto.signDetached(hashToSign, privateSigningKeyBytes)
    const fullSignature = await this.crypto.b64encode(fullSigRaw)
    const authHeader = `${headerString}; ${fullSignature}`
    return authHeader
  }

  canPerformTokenAuth() {
    return !(this.apiKeyId === undefined) && !(this.apiSecret === undefined)
  }

  /**
   * Wrapper method to cache and generate the Authentication header using oAuth
   * Throws if auth object is missing needed API keys
   *
   * @returns {Promise<string>} Promise of a valid authentication header
   */
  async getTokenHeader() {
    if (this._authToken === null || Date.now() > this._authTokenTimeout) {
      if (this.canPerformTokenAuth()) {
        return 'Bearer ' + (await this.tokenAuth())
      }
      throw new Error('Missing needed API keys to perform token auth')
    }
    return Promise.resolve('Bearer ' + this._authToken)
  }

  /**
   * Retrieves token for an API key and secret
   *
   * @returns {Promise<string>} Promise of a valid authentication header
   */
  async tokenAuth() {
    let response
    response = await fetch(this.apiUrl + '/v1/auth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'x-www-form-urlencoded',
        Authorization: 'Basic ' + btoa(this.apiKeyId + ':' + this.apiSecret)
      },
      body: 'grant_type=client_credentials'
    })
    let json = await response.json()
    this._authToken = json.access_token
    this._authTokenTimeout = Date.parse(json.expires_at)
    return this._authToken
  }
}

module.exports = Auth
