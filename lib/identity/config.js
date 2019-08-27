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

import { DEFAULT_API_URL } from '../utils/constants'

/**
 * Configuration and credentials for E3DB.
 *
 * @property {string} realmId   The realm's unique identifier
 * @property {string} realmName The realm's globally unique name
 * @property {string} userId    The specific realm users unique identifier
 * @property {string} [apiUrl]  Optional base URL for the Tozny Platform API
 */
export default class Config {
  /**
   * Create a new config object from a JSON string or JS object.
   *
   * If a string is passed, it is first parsed as JSON into an object.
   *
   * Camel case version of object keys are checked first. If the camel case version
   * of the configuration key is undefined, this method falls back to the snake case
   * version of the supported keys.
   *
   * @param {Object|string} obj A JSON string or javascript object containing identity configuration.
   *
   * @returns {Config} A new Config object based on the passed JS object or JSON string.
   */
  static fromObject(obj) {
    if (typeof obj === 'string') {
      try {
        obj = JSON.parse(obj)
      } catch (err) {
        throw new Error('Config.fromObject param JSON string could not be parsed.')
      }
    }
    const realmId = obj.realmId || obj.realm_id
    const realmName = obj.realmName || obj.realm_name
    const userId = obj.userId || obj.user_id
    const apiUrl = obj.apiUrl || obj.api_url
    return new this(realmId, realmName, userId, apiUrl)
  }

  /**
   * Create a new instance of Config
   *
   * @param {string} realmId   The realm's unique identifier
   * @param {string} realmName The realms globally unique name
   * @param {string} userId    A specific realm user's unique identifier
   * @param {string} [apiUrl]  Optional base URL for the Tozny Platform API
   *
   * @returns {Config} The constructed Config object.
   */
  constructor(realmId, realmName, userId, apiUrl = DEFAULT_API_URL) {
    console.log('[IdentityConfig constructor] attempting call constructor')
    this.realmId = realmId
    this.realmName = realmName
    this.userId = userId
    this.apiUrl = apiUrl
  }

  /**
   * Creates a copy of the current configuration overriding values with the passed object.
   *
   * @param {Object} [overrides] An optional object overriding any specific configuration values.
   *
   * @returns {Config} A new instance of the Config object defined values overridden.
   */
  clone(overrides = {}) {
    return this.constructor.fromObject(Object.assign(this, overrides))
  }
}
