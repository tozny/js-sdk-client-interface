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

import Client from './client'
import Config from './config'
import 'isomorphic-fetch'
import { Config as StorageConfig } from '../storage'
import CryptoConsumer from '../utils/cryptoConsumer'

// Helper method for creating a billing client
function createClient(billing, storageConfig) {
  const billingConfig = billing.config.clone()
  const storageClient = new billing.StorageClient(storageConfig)
  return new Client(billingConfig, storageClient, billing.crypto)
}

export default class Billing extends CryptoConsumer {
  static isExtension(billing) {
    return billing.prototype instanceof Billing
  }

  static get Client() {
    return Client
  }

  static get Config() {
    return Config
  }

  /**
   * Abstract getter for a storage Client constructor function.
   *
   * When implementing this class, this getter must be overloaded. When called it
   * should offer up a storage Client constructor function. Billing constructs
   * storage clients as part of creating Billing clients.
   *
   * An additional instance level getter is also provided which allows fetching
   * the storage client constructor in both static _and_ instance method
   * contexts as `this.StorageClient`.
   *
   * @returns {Client} The storage Client constructor.
   */
  static get StorageClient() {
    throw new Error(
      'Implementing classes must overloaded the StorageClient method to provide a valid storage Client constructor.'
    )
  }

  constructor(config) {
    super()
    this.config = config
  }

  /**
   * Allows `this.StorageClient` syntax in instance methods.
   *
   * Gets the static StorageClient constructor available in the static class. By
   * returning it as a getter `this.StorageClient` syntax is support in
   * instance methods.
   *
   * @returns {Client} The storage Client constructor.
   */
  get StorageClient() {
    // Use this.constructor to ensure we referencing the implementing class, not an interface class.
    return this.constructor.StorageClient
  }

  fromObject(obj) {
    if (typeof obj === 'string') {
      try {
        obj = JSON.parse(obj)
      } catch (err) {
        throw new Error('Config.fromObject param JSON string could not be parsed.')
      }
    }
    if (!obj.config) {
      throw new Error(
        'To create a billing client from an object it must contain billing configuration'
      )
    }
    if (!obj.storageConfig) {
      throw new Error(
        'To create a billing client from an object it must contain storageConfig with valid Storage Client configuration'
      )
    }

    return createClient(this, StorageConfig.fromObject(obj.storageConfig))
  }
}
