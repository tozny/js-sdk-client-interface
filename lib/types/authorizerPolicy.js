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

/**
 * Information an authorizer policy written to TozStore
 *
 * @property {string} authorizerId The Client ID controlled by the policy
 * @property {string} writerId The client ID that wrote the data controlled by the policy
 * @property {string} userId The client ID the data controlled by the policy is about
 * @property {string} recordType The record type controlled by the policy
 * @property {string} authorizedBy The Client ID that wrote the policy
 */
export default class AuthorizerPolicy {
  constructor(authorizerId, writerId, userId, recordType, authorizedBy) {
    this.authorizerId = authorizerId
    this.writerId = writerId
    this.userId = userId
    this.recordType = recordType
    this.authorizedBy = authorizedBy
  }

  /**
   * Specify how an already unserialized JSON array should be marshaled into
   * an object representation.
   *
   * @param {object} json
   *
   * @return {AuthorizerPolicy}
   */
  static decode(json) {
    return new AuthorizerPolicy(
      json.authorizer_id,
      json.writer_id,
      json.user_id,
      json.record_type,
      json.authorized_by
    )
  }
}
