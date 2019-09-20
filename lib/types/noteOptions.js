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
import EACP from './eacp'

/**
 * NoteOptions represents optional values that are not required for creating a note,
 * but provide additional functionality. Some features are premium and require a TozStore client to work.
 */
export default class NoteOptions extends Serializable {
  constructor(
    clientId,
    maxViews,
    idString,
    expiration,
    expires,
    type,
    plain,
    fileMeta,
    eacp
  ) {
    super()

    // Premium features
    this.clientId = clientId
    this.maxViews = maxViews
    this.idString = idString // User defined id (id_string) available as part of premium features.
    this.expiration = expiration
    this.expires = expires
    this.eacp = eacp

    // Non-premium
    this.type = type
    this.plain = plain
    this.fileMeta = fileMeta
  }

  serializable() {
    /* eslint-disable camelcase */
    let toSerialize = {
      client_id: this.clientId,
      max_views: this.maxViews,
      id_string: this.idString,
      expiration: this.expiration,
      expires: this.expires,
      type: this.type
    }
    // Ensure that plainMeta is always an object, even it it's set to null
    if (this.plain === null) {
      toSerialize.plain = {}
    } else {
      toSerialize.plain = this.plain
    }

    // Ensure that fileMeta is always an object, even it it's set to null
    if (this.fileMeta === null) {
      toSerialize.file_meta = {}
    } else {
      toSerialize.file_meta = this.fileMeta
    }
    /* eslint-enabled */

    if (this.eacp instanceof EACP) {
      toSerialize.eacp = this.eacp.serializable()
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
    let type = json.type === undefined ? null : json.type
    let plain = json.plain === undefined ? {} : json.plain
    let fileMeta = json.file_meta === undefined ? {} : json.file_meta
    let clientId = json.client_id === undefined ? undefined : json.client_id
    let maxViews = json.max_views === undefined ? null : json.max_views
    let idString = json.id_string === undefined ? null : json.id_string
    let expiration = json.expiration === undefined ? null : json.expiration
    let expires = json.expires === undefined ? null : json.expires
    let eacp = json.eacp === undefined ? null : EACP.decode(json.eacp)
    return new NoteOptions(
      clientId,
      maxViews,
      idString,
      expiration,
      expires,
      type,
      plain,
      fileMeta,
      eacp
    )
  }
}
