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
import { validateResponseAsJSON } from '../utils'
import { deriveNoteCreds } from '../utils/credentials'
import CryptoConsumer from '../utils/cryptoConsumer'
import { Config as StorageConfig } from '../storage'
import { PublicKey, SigningKey } from '../types'

function createClient(id, userId, storageConfig) {
  const idConfig = id.config.clone({ userId: userId })
  const storageClient = new id.StorageClient(storageConfig)
  return new Client(idConfig, storageClient, id.crypto)
}

export default class Identity extends CryptoConsumer {
  static isExtension(identity) {
    return identity.prototype instanceof Identity
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

  async register(username, password, token, email) {
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
    const json = await validateResponseAsJSON(request)
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
      this.config,
      this.crypto,
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
    const brokerClientID = '00000000-0000-0000-0000-000000000000'
    const brokerInfo = idClient.storageClient.clientInfo(brokerClientID)
    const brokerKeyNoteName = await this.crypto.genericHash(
      `broker${username}${this.config.realmId}key`
    )
    const brokerKeyBytes = await this.crypto.randomBytes(64)
    const brokerKey = await this.crypto.b64encode(brokerKeyBytes)
    const brokerNoteCreds = await deriveNoteCreds(
      this.config,
      this.crypto,
      username,
      brokerKey,
      true
    )
    /* eslint-disable camelcase */
    const brokerKeyNote = await idClient.storageClient.writeNote(
      { brokerKey, username },
      brokerInfo.publicKey.curve25519,
      brokerInfo.signing_key.ed25519,
      {
        id_string: brokerKeyNoteName,
        max_views: -1,
        expires: false,
        eacp: {
          email_otp: {
            email_address: email,
            template: 'password_recovery',
            provider_link: this.config.brokerTargetUrl
          }
        }
      }
    )
    await idClient.storageClient.writeNote(
      idClient.serialize(),
      brokerNoteCreds.cryptoKeyPair.publicKey,
      brokerNoteCreds.signingKeyPair.publicKey,
      {
        id_string: brokerNoteCreds.noteID,
        max_views: -1,
        expires: false,
        eacp: {
          note_access: {
            note_id: brokerKeyNote.noteId
          }
        }
      }
    )
    /* eslint-enable */

    return idClient
  }

  async login(username, password, broker = false) {
    const { noteID, cryptoKeyPair, signingKeyPair } = await deriveNoteCreds(
      this.config,
      this.crypto,
      username,
      password,
      broker
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
        'To create an identity client from an object it must contain identity configuration'
      )
    }
    if (!obj.storageConfig) {
      throw new Error(
        'To create an identity client from an object it must contain storageConfig with valid Storage Client configuration'
      )
    }
    /* eslint-disable-next-line no-warning-comments */
    // TODO: Validate creds match this realm before instantiating
    return createClient(
      this,
      obj.config.userId,
      StorageConfig.fromObject(obj.storageConfig)
    )
  }

  initiateRecovery(username, recoveryUrl) {
    return this.initiateBrokerLogin(username, recoveryUrl)
  }

  completeRecovery(otp, noteId, recoveryUrl) {
    return this.completeBrokerLogin(otp, noteId, recoveryUrl)
  }

  async initiateBrokerLogin(
    username,
    brokerUrl = `${this.config.apiUrl}/v1/identity/${this.config.realmId}/broker`
  ) {
    const payload = {
      username,
      action: 'initiate'
    }
    const request = await fetch(brokerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
    return validateResponseAsJSON(request)
  }

  async completeBrokerLogin(
    authResponse,
    noteId,
    brokerUrl = `${this.config.apiUrl}/v1/identity/${this.config.realmId}/broker`
  ) {
    // Generate ephemeral keys for broker key transfer
    const cryptoKeys = await this.StorageClient.generateKeypair()
    const signingKeys = await this.StorageClient.generateSigningKeypair()
    // Request the broker write the key transfer note.
    /* eslint-disable camelcase */
    const payload = {
      auth_response: authResponse,
      note_id: noteId,
      public_key: new PublicKey(cryptoKeys.publicKey),
      signing_key: new SigningKey(signingKeys.publicKey),
      action: 'complete'
    }
    /* eslint-enable */
    const request = await fetch(brokerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
    const { transferId } = await validateResponseAsJSON(request)
    // Fetch the broker key transfer note
    const brokerKeyNote = await this.StorageClient.readNote(
      transferId,
      cryptoKeys,
      signingKeys,
      this.config.apiUrl
    )
    const { brokerKey, username } = brokerKeyNote.data
    // Use the broker key to complete the login flow
    return this.login(username, brokerKey, true)
  }
}
