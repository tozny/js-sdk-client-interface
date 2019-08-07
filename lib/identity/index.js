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

import Client from './client'
import Config from './config'
import 'isomorphic-fetch'
import { checkStatus } from '../utils'
import CryptoConsumer from '../utils/cryptoConsumer'
import { Config as StorageConfig } from '../storage'
import { PublicKey, SigningKey } from '../types'

async function deriveNoteCreds(id, username, password) {
  const noteID = await id.crypto.genericHash(username + id.config.realmId)
  const cryptoKeyPair = await id.crypto.deriveCryptoKey(
    password,
    id.config.realmId + id.config.realmName,
    10000
  )
  const signingKeyPair = await id.crypto.deriveSigningKey(
    password,
    cryptoKeyPair.publicKey + cryptoKeyPair.privateKey,
    10000
  )
  return { noteID, cryptoKeyPair, signingKeyPair }
}

function createClient(id, userId, storageConfig) {
  const idConfig = id.config.clone({ userId: userId })
  const storageClient = new id.StorageClient(storageConfig)
  return new Client(idConfig, storageClient, id.crypto)
}

export default class Identity extends CryptoConsumer {
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
   * should offer up a storage Client constructor function. Identity constructs
   * storage clients as part of creating Identity clients.
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

  async register(username, password, token) {
    const cryptoKeys = await this.StorageClient.generateKeypair()
    const signingKeys = await this.StorageClient.generateSigningKeypair()
    /* eslint-disable camelcase */
    const payload = {
      realm_registration_token: token,
      realm_id: this.config.realmId,
      identity: {
        realm_id: this.config.realmId,
        name: username,
        public_key: new PublicKey(cryptoKeys.publicKey),
        signing_key: new SigningKey(signingKeys.publicKey)
      }
    }
    /* eslint-enable */
    const request = await fetch(this.config.apiUrl + '/v1/identity/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
    const response = await checkStatus(request)
    const json = await response.json()
    const idClient = createClient(
      this,
      json.identity.id,
      new StorageConfig(
        json.identity.tozny_id,
        json.identity.api_key_id,
        json.identity.api_secret_key,
        cryptoKeys.publicKey,
        cryptoKeys.privateKey,
        this.config.apiUrl,
        signingKeys.publicKey,
        signingKeys.privateKey
      )
    )
    // Login note
    const { noteID, cryptoKeyPair, signingKeyPair } = await deriveNoteCreds(
      this,
      username,
      password
    )
    /* eslint-disable camelcase */
    await idClient.storageClient.writeNote(
      idClient.serialize(),
      cryptoKeyPair.publicKey,
      signingKeyPair.publicKey,
      {
        id_string: noteID,
        max_views: -1,
        expires: false
      }
    )
    /* eslint-enable */
    /* eslint-disable-next-line no-warning-comments */
    // TODO: Write recovery note based on final parameters
    return idClient
  }

  async login(username, password) {
    const { noteID, cryptoKeyPair, signingKeyPair } = await deriveNoteCreds(
      this,
      username,
      password
    )
    const storedCreds = await this.StorageClient.readNoteByName(
      noteID,
      cryptoKeyPair,
      signingKeyPair,
      this.config.apiUrl
    )
    const idConfig = Config.fromObject(storedCreds.data.config)

    /* eslint-disable-next-line no-warning-comments */
    // TODO: Validate creds match this realm before instantiating
    return createClient(
      this,
      idConfig.userId,
      StorageConfig.fromObject(storedCreds.data.storageConfig)
    )
  }
}
