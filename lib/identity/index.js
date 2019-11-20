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
import { validateResponseAsJSON, trimSlash, checkStatus } from '../utils'
import { deriveNoteCreds } from '../utils/credentials'
import CryptoConsumer from '../utils/cryptoConsumer'
import { Config as StorageConfig } from '../storage'
import { PublicKey, SigningKey } from '../types'

/**
 * Identity represents a connection to the Tozny Identity service on behalf of a realm.
 *
 * Before registration, login, or other client creation methods are possible, the configuration
 * for a Tozny Identity realm is needed. Identity holds this configuration and provides methods
 * for all pre-client operations. In other words, the methods this object make identity clients
 * for users that belong to the configured realm. It helps authenticate users.
 */
export default class Identity extends CryptoConsumer {
  /**
   * Check whether a variable is an Identity instance.
   *
   * @param {*} identity an object that may or may not be an instance of Identity.
   *
   * @return {boolean} Whether or not the passed item is an instance of Identity.
   */
  static isExtension(identity) {
    return identity.prototype instanceof Identity
  }

  /**
   * Gets the Client constructor for creating identity Clients.
   *
   * @return {Function} The constructor function for creating a Client instance.
   */
  static get Client() {
    return Client
  }

  /**
   * Gets the Config constructor for creating Identity configuration objects.
   *
   * @return {Function} The identity Config constructor function.
   */
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
   * @return {Client} The storage Client constructor.
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

  /**
   * Register a new identity with the Tozny identity service.
   *
   * This method creates a new identity service user and associated storage identity. Using the
   * passed username and password it derives encryption keys and writes those credentials to a
   * Tozny Storage Secure Note. This note is fetch-able using the username/password derived keys.
   *
   * It also create a broker-based set of recovery notes protected by the provided email that are
   * used to recover the account in the event the user forgets their password.
   *
   * Finally, the fully constructed Client for the user is returned, ready to make requests using
   * the user identity that was just created.
   *
   * @param {string} username The name to associate with the user in the configured realm.
   *                          may be the same as the email value.
   * @param {string} password The secret used to protect the users identity and encryption keys.
   * @param {string} token The registration token to create the storage client with.
   * @param {string} email The email address used for email brokered access to the identity.
   *
   * @return {Client} The identity Client for the user that was just registered with the realm.
   */
  async register(username, password, token, email) {
    const cryptoKeys = await this.StorageClient.generateKeypair()
    const signingKeys = await this.StorageClient.generateSigningKeypair()
    /* eslint-disable camelcase */
    const payload = {
      realm_registration_token: token,
      realm_name: this.config.realmName,
      identity: {
        realm_name: this.config.realmName,
        name: username,
        public_key: new PublicKey(cryptoKeys.publicKey),
        signing_key: new SigningKey(signingKeys.publicKey),
      },
    }
    /* eslint-enable */
    const request = await fetch(this.config.apiUrl + '/v1/identity/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    })
    const json = await validateResponseAsJSON(request)
    const idConfig = this.config.clone({ username, userId: json.identity.id })
    const storageClientConfig = new StorageConfig(
      json.identity.tozny_id,
      json.identity.api_key_id,
      json.identity.api_secret_key,
      cryptoKeys.publicKey,
      cryptoKeys.privateKey,
      this.config.apiUrl,
      signingKeys.publicKey,
      signingKeys.privateKey
    )
    const storageClient = new this.StorageClient(storageClientConfig)
    const idClient = new Client(idConfig, storageClient, this.crypto)
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
        expires: false,
      }
    )
    /* eslint-enable */
    const brokerClientID = json.realm_broker_identity_tozny_id
    // If there is no broker, do not try to write broker notes
    if (brokerClientID === '00000000-0000-0000-0000-000000000000') {
      return idClient
    }

    // Write notes for broker email password reset flow
    const brokerInfo = await idClient.storageClient.clientInfo(brokerClientID)
    const brokerKeyNoteName = await this.crypto.genericHash(
      `brokerKey:${username}@realm:${this.config.realmName}`
    )
    const brokerKeyBytes = await this.crypto.randomBytes(64)
    const brokerKey = await this.crypto.b64encode(brokerKeyBytes)
    const brokerNoteCreds = await deriveNoteCreds(
      this.config,
      this.crypto,
      username,
      brokerKey,
      'email_otp'
    )
    /* eslint-disable camelcase */
    const brokerKeyNote = await idClient.storageClient.writeNote(
      { brokerKey, username },
      brokerInfo.publicKey.curve25519,
      brokerInfo.signingKey.ed25519,
      {
        id_string: brokerKeyNoteName,
        max_views: -1,
        expires: false,
        eacp: {
          email_eacp: {
            email_address: email,
            template: 'password_reset',
            provider_link: this.config.brokerTargetUrl,
          },
        },
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
          last_access_eacp: {
            last_read_note_id: brokerKeyNote.noteId,
          },
        },
      }
    )
    /* eslint-enable */

    // Write notes for Tozny OTP based broker password reset flow
    const brokerToznyOTPKeyNoteName = await this.crypto.genericHash(
      `broker_otp:${username}@realm:${this.config.realmName}`
    )
    const brokerToznyOTPKeyBytes = await this.crypto.randomBytes(64)
    const brokerToznyOTPKey = await this.crypto.b64encode(
      brokerToznyOTPKeyBytes
    )
    const brokerToznyOTPNoteCreds = await deriveNoteCreds(
      this.config,
      this.crypto,
      username,
      brokerToznyOTPKey,
      'tozny_otp'
    )
    /* eslint-disable camelcase */
    const brokerToznyOTPKeyNote = await idClient.storageClient.writeNote(
      { brokerKey: brokerToznyOTPKey, username },
      brokerInfo.publicKey.curve25519,
      brokerInfo.signingKey.ed25519,
      {
        id_string: brokerToznyOTPKeyNoteName,
        max_views: -1,
        expires: false,
        eacp: {
          tozny_otp_eacp: {
            include: true,
          },
        },
      }
    )
    await idClient.storageClient.writeNote(
      idClient.serialize(),
      brokerToznyOTPNoteCreds.cryptoKeyPair.publicKey,
      brokerToznyOTPNoteCreds.signingKeyPair.publicKey,
      {
        id_string: brokerToznyOTPNoteCreds.noteID,
        max_views: -1,
        expires: false,
        eacp: {
          last_access_eacp: {
            last_read_note_id: brokerToznyOTPKeyNote.noteId,
          },
        },
      }
    )
    /* eslint-enable */

    return idClient
  }

  /**
   * Get the stored identity credentials for a user and create a Client for them.
   *
   * The username and password are used to derive encryption keys used to fetch a pre-stored
   * note which contains the users identity credentials.
   *
   * Broker mode is used when another identity holds the seed (password) used for
   * the login. Standard login flows with username and password should always use
   * `broker = false` or omit the parameter.
   *
   * @param {string} username The username of the identity to create a Client for.
   * @param {string} password The secret password of the identity to create a Client for.
   * @param {boolean} credentialType What style credentials to complete the login with `password` for normal logins.
   *
   * @return {Client} The identity Client object for the user.
   */
  async login(username, password, credentialType = 'password') {
    const { noteID, cryptoKeyPair, signingKeyPair } = await deriveNoteCreds(
      this.config,
      this.crypto,
      username,
      password,
      credentialType
    )
    const storedCreds = await this.StorageClient.readNoteByName(
      noteID,
      cryptoKeyPair,
      signingKeyPair,
      this.config.apiUrl
    )

    const user = this.fromObject(storedCreds.data)
    // User can belong to multiple appNames (keycloak clients), but the app we're
    // accessing is defined in our config not the config written at register time.
    user.config.clone({ appName: this.config.appName })

    // Backwards compatibility for any identity user whose username was not
    // written to the credentials note.
    if (user.config.username !== username) {
      user.config.username = username
    }

    return user
  }

  /**
   * Recreate a identity Client from a serialized representation.
   *
   * When storing an identity client, this method will reconstitute the Client from
   * a serialized representation. The plain JS object is unpacked a new, fully ready
   * Client instance is returned based on the serialized values.
   *
   * @param {Object} obj The serialized Javascript object representing a user.
   *
   * @return {Client} The reconstituted identity client for the user.
   */
  fromObject(obj) {
    // Allow JSON string objects for ease of use.
    if (typeof obj === 'string') {
      try {
        obj = JSON.parse(obj)
      } catch (err) {
        throw new Error(
          'Config.fromObject param JSON string could not be parsed.'
        )
      }
    }
    // Ensure object shape is generally correct
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

    // Set up identity client config
    const idConfig = this.constructor.Config.fromObject(obj.config)
    // Validate the configuration matches this realm
    if (trimSlash(idConfig.apiUrl) !== trimSlash(this.config.apiUrl)) {
      throw new Error('The client and realm must use the same api url')
    }
    if (idConfig.realmName !== this.config.realmName) {
      throw new Error(
        'only clients from the configured realm can be instantiated.'
      )
    }

    // Set up storage client
    const storageClientConfig = StorageConfig.fromObject(obj.storageConfig)
    const storageClient = new this.StorageClient(storageClientConfig)
    // Create the realm client
    return new Client(idConfig, storageClient, this.crypto)
  }

  /**
   * A wrapper around the broker login flow used for email account recovery.
   *
   * @param {string} username The username to recover.
   * @param {string} recoveryUrl The URL to send the reset initiation to.
   */
  initiateRecovery(username, recoveryUrl) {
    return this.initiateBrokerLogin(username, recoveryUrl)
  }

  /**
   * A wrapper around the completion of a broker flow used for email account recovery.
   *
   * Once complete a password update should immediately be initiated for the user.
   *
   * @param {string} otp The one-time password from the email challenge issued.
   * @param {string} noteId The ID of the note the email challenge was for.
   * @param {string} recoveryUrl The URL to send the recovery authentication to.
   * @param {string} recoveryType The recovery type used either "tozny_otp" | "email_otp"
   *
   * @return{Promise<Client>} The recovered identity Client.
   */
  completeRecovery(otp, noteId, recoveryUrl, recoveryType) {
    /* eslint-disable camelcase */
    return this.completeBrokerLogin(
      { [recoveryType]: otp },
      noteId,
      recoveryUrl,
      recoveryType
    )
    /* eslint-enable */
  }

  /**
   * Begin a broker-based login flow.
   *
   * Broker flows are when another party holds the seed material used to access an
   * identity account. The broker's access to the seed material is generally protected
   * by an extra policy check controlled by the user. The initiation request informs
   * the broker that the user wishes to collect their seed, which causes the broker
   * to initiate any challenges required by to access the seed material.
   *
   * @param {string} username The username of the user wishing to access their credentials.
   * @param {string} brokerUrl The URL where the broker can be contacted.
   */
  async initiateBrokerLogin(
    username,
    brokerUrl = `${this.config.apiUrl}/v1/identity/broker/realm/${this.config.realmName}/challenge`
  ) {
    const payload = {
      username,
      action: 'challenge',
    }
    const request = await fetch(brokerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    })
    await checkStatus(request)
    return request.status === 200 ? request.json() : true
  }

  /**
   * Complete a broker based login flow by giving the broker the needed authentication information.
   *
   * After initiating a broker-based login, the storage system will issue a challenge to the user,
   * such as an email containing a one-time password. This information is passed back to the broker
   * proving the user has granted them access to the seed material. The broker then encrypts and
   * returns the seed to the user who is then able to derive the keys needed to fetch their identity
   * credentials and create a Client instance.
   *
   * @param {*} authResponse The authentication material to allow a broker to access the seed material.
   * @param {string} noteId The ID of the note containing the seed material.
   * @param {string} brokerUrl The URL where the broker can be contacted.
   *
   * @return {Client} An identity Client for the user.
   */
  async completeBrokerLogin(
    authResponse,
    noteId,
    brokerUrl = `${this.config.apiUrl}/v1/identity/broker/realm/${this.config.realmName}/login`,
    brokerType = 'email_otp'
  ) {
    // Generate ephemeral keys for broker key transfer
    const cryptoKeys = await this.StorageClient.generateKeypair()
    const signingKeys = await this.StorageClient.generateSigningKeypair()
    // Request the broker write the key transfer note.
    /* eslint-disable camelcase */
    const payload = {
      auth_response: authResponse,
      note_id: noteId,
      public_key: cryptoKeys.publicKey,
      signing_key: signingKeys.publicKey,
      action: 'login',
    }
    /* eslint-enable */
    const request = await fetch(brokerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
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
    return this.login(username, brokerKey, brokerType)
  }
}
