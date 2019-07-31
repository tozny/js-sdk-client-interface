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

/*
 * CoreNote represents required note information that is signed before encrypting
 */
export default class NoteOptions extends Serializable {
  constructor(clientId, maxViews, idString, expiration) {
    super()

    this.clientId = clientId
    this.maxViews = maxViews
    this.idString = idString // User defined id (id_string) available as part of premium features.
    this.expiration = expiration
  }

  serializable() {
    let toSerialize = {
      client_id: this.clientId,
      max_views: this.maxViews,
      id_string: this.idString,
      expiration: this.expiration
    }

    const serializedKeys = Object.keys(toSerialize)
    for (const key of serializedKeys) {
      if (toSerialize[key] === null) {
        delete toSerialize[key]
      }
    }
    return toSerialize
  }

  static decode(json) {
    let clientId = json.client_id === undefined ? null : json.client_id
    let maxViews = json.max_views === undefined ? null : json.max_views
    let idString = json.id_string === undefined ? null : json.id_string
    let expiration = json.expiration === undefined ? null : json.expiration
    return new NoteOptions(clientId, maxViews, idString, expiration)
  }
}
