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

import Crypto from '../crypto'
import Config from '../config'

/**
 * Ensures a crypto instance is actually a crypto instance, throwing if it is not.
 * @param {Crypto} c The crypto instance to check
 */
export function checkCrypto(c) {
  if (!(c instanceof Crypto)) {
    throw new Error('Must pass a valid Crypto object')
  }
}

/**
 * Ensures a config instance is actually a config instance, throwing if it is not.
 * @param {Config} c The config instance to check
 */
export function checkConfig(c) {
  if (!(c instanceof Config)) {
    throw new Error('Must pass a valid Config object')
  }
}

/**
 * Fallback polyfill to allow for HTTP Basic authentication from either Node
 * or browser-based JavaScript.
 *
 * @param {string} str String to encode as Base64
 */
export function btoa(str) {
  let buf = Buffer.from(str, 'utf8')
  return buf.toString('base64')
}

/**
 * Check the return status of a fetch request and throw an error if one occurred
 *
 * @param {Response} response
 *
 * @returns {Promise}
 */
export async function checkStatus(response) {
  if (response.status >= 200 && response.status < 300) {
    return Promise.resolve(response)
  }

  let error = new Error(response.statusText)
  error.response = response
  throw error
}
