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

class Auth {
  constructor(
    apiKeyID,
    apiSecret,
    publicSigningKey,
    privateSigningKey,
    crypto,
    apiUrl,
  ) {
    this.apiKeyID = apiKeyID
    this.apiSecret = apiSecret
    this.publicSigningKey = publicSigningKey
    this.privateSigningKey = privateSigningKey
    this.apiUrl = apiUrl
    this.crypto = crypto
    this._authToken = null
    this._authTokenTimeout = 0 // Minimum UNIX timestamp
  }

  async authenticate(urlString, options) {
    if (this.canPerformSignatureAuth(urlString, options)) {
      return this.signatureAuth(urlString, options)
    }
    if (this.canPerformTokenAuth()) {
      return this.tokenAuth
    }
    throw new Error('This client is missing the keys to perform any supported authentication method')
  }

  canPerformSignatureAuth(urlString, options) {
    return !(this.publicSigningKey === undefined) && !(this.privateSigningKey === undefined) && !(urlString === undefined) && !(options === undefined)
  }

  async getSignatureHeader(urlString, options) {
    if (this.CanPerformSignatureAuth(urlString, options)) {
      return this.signatureAuth(urlString, options)
    }
    throw new Error('Missing public or private signing key')
  }

  signatureAuth(urlString, options) {
	const url = new URL(urlString)
	// This currently requires a trailing slash because of how Go redirects
	// requests without a trailing slash. Strange little bug that should be dug
	// out, but for now works if you include the trailing slash in the URL.
	const path = url.pathname
	// This is not the right way to get this query string. The string should be
	// sorted correctly per the spec. Doing it this way requires the params are
	// declared in the right order and encoded correctly. This works for a POC.
    const queryString = url.search.substr(1)

	const timestamp = Date.now() / 1000 | 0
	// Hard code the sodium ciphers for now as they are the only ones supported.
	const authMethod = "TSV1-ED25519-BLAKE2B"
	const nonce = uuid()
	const user = ""
	const headerString = `${authMethod}; ${this.publicSigningKey}; ${timestamp}; ${nonce}; uid:${user}`
	const strToSign = `${path}; ${queryString}; ${options.method}; ${headerString}`
	const hashToSign = await this.crypto.genericHash(strToSign)
	const fullSigRaw = this.crypto.signDetached(hashToSign, this.privateSigningKey)
	const fullSig = await this.crypto.b64encode(fullSigRaw)
    const authHeader = `${headerString}; ${fullSig}`
    return authHeader
  }

  canPerformTokenAuth() {
    return !(this.apiKeyID === undefined) && !(this.apiSecret === undefined)
  }

  getTokenHeader() {
    if (this._authToken === null || Date.now() > this._authTokenTimeout) {
        if (this.canPerformTokenAuth()) {
          return this.tokenAuth()
        }
        throw new Error('Missing needed API keys to perform token auth')
    }
    return this._authToken
  }

  async tokenAuth() {
    let response
    response = await fetch(this.apiUrl + "/v1/auth/token", {
    method: "POST",
    headers: {
        "Content-Type": "x-www-form-urlencoded",
        Authorization: "Basic " + btoa(this.apiKeyId + ":" + this.apiSecret)
    },
    body: "grant_type=client_credentials"
    })
    let json = await response.json()
    this._authToken = "Bearer " + json.access_token
    this._authTokenTimeout = Date.parse(json.expires_at)
    return this._authToken
  }
}

module.exports = Auth
