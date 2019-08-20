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

import 'es6-promise/auto'
import 'isomorphic-fetch'

import AuthenticatedRequest from '../utils/authenticatedRequest'
import CryptoConsumer from '../utils/cryptoConsumer'
import Config from './config'
import { checkStatus } from '../utils'
import { DEFAULT_API_URL, DEFAULT_QUERY_COUNT, EMAIL } from '../utils/constants'
import {
  ClientDetails,
  ClientInfo,
  EAKInfo,
  File,
  IncomingSharingPolicy,
  Meta,
  OutgoingSharingPolicy,
  PublicKey,
  Query,
  QueryResult,
  Record,
  RecordData,
  RecordInfo,
  SignedDocument,
  SigningKey,
  KeyPair,
  Note,
  NoteData,
  NoteInfo,
  NoteKeys,
  NoteOptions
} from '../types'

/**
 * Retrieve an access key from the server.
 *
 * @param {Client} client E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 *
 * @returns {Promise<EAKInfo|null>} Encrypted access key on success, NULL if no key exists.
 */
async function getEncryptedAccessKey(client, writerId, userId, readerId, type) {
  let response = await client.authenticator.tokenFetch(
    client.config.apiUrl +
      '/v1/storage/access_keys/' +
      writerId +
      '/' +
      userId +
      '/' +
      readerId +
      '/' +
      type,
    {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  )
  if (response.status && response.status === 404) {
    return Promise.resolve(null)
  }

  return checkStatus(response)
    .then(response => response.json())
    .then(eak => EAKInfo.decode(eak))
}

/**
 * Retrieve an access key from the server.
 *
 * @param {Client} client E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 *
 * @returns {Promise<string|null>} Decrypted access key on success, NULL if no key exists.
 */
async function getAccessKey(client, writerId, userId, readerId, type) {
  let cacheKey = `${writerId}.${userId}.${type}`
  if (client._akCache[cacheKey] !== undefined) {
    return Promise.resolve(client._akCache[cacheKey])
  }
  return getEncryptedAccessKey(client, writerId, userId, readerId, type)
    .then(eak => {
      if (eak === null) {
        return Promise.resolve(null)
      }
      return client.crypto.decryptEak(client.config.privateKey, eak)
    })
    .then(key => {
      if (key !== null) {
        client._akCache[cacheKey] = key
      }
      return Promise.resolve(key)
    })
    .catch(err => console.log(err))
}

/**
 * Create an access key on the server.
 *
 * @param {Client} client   E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 * @param {string} ak       Unencrypted access key

 @returns {Promise<string>} Decrypted access key
 */
async function putAccessKey(client, writerId, userId, readerId, type, ak) {
  let clientInfo = await client.getClient(readerId)
  let readerKey = clientInfo.publicKey.curve25519
  let eak = await client.crypto.encryptAk(client.config.privateKey, ak, readerKey)
  return client.authenticator
    .tokenFetch(
      client.config.apiUrl +
        '/v1/storage/access_keys/' +
        writerId +
        '/' +
        userId +
        '/' +
        readerId +
        '/' +
        type,
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ eak: eak })
      }
    )
    .then(checkStatus)
    .then(() => {
      let cacheKey = `${writerId}.${userId}.${type}`
      client._akCache[cacheKey] = ak

      return Promise.resolve(ak)
    })
}

/**
 * Delete an access key on the server.
 *
 * @param {Client} client   E3DB client instance
 * @param {string} writerId Writer/Authorizer for the access key
 * @param {string} userId   Record subject
 * @param {string} readerId Authorized reader
 * @param {string} type     Record type for which the key will be used
 *
 * @returns {Promise<bool>}
 */
async function deleteAccessKey(client, writerId, userId, readerId, type) {
  let request = await client.authenticator.tokenFetch(
    client.config.apiUrl +
      '/v1/storage/access_keys/' +
      writerId +
      '/' +
      userId +
      '/' +
      readerId +
      '/' +
      type,
    {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  )

  await checkStatus(request)

  let cacheKey = `${writerId}.${userId}.${type}`
  delete client._akCache[cacheKey]

  return true
}

/**
 * Fetch the access key for a record type and use it to decrypt a given record.
 *
 * @param {Client} client E3DB client instance
 * @param {Record} encrypted Record to be decrypted
 *
 * @return {Promise<Record>}
 */
async function decryptRecord(client, encrypted) {
  let ak = await getAccessKey(
    client,
    encrypted.meta.writerId,
    encrypted.meta.userId,
    client.config.clientId,
    encrypted.meta.type
  )
  if (ak === null) {
    throw new Error('No access key available.')
  }

  return client.crypto.decryptRecord(encrypted, ak)
}

/**
 * Fetch the access key for a record type and use it to encrypt a given record.
 *
 * @param {Client} client E3DB client instance
 * @param {Record} record Record to be decrypted
 *
 * @return {Promise<Record>}
 */
async function encryptRecord(client, record) {
  let ak = await getAccessKey(
    client,
    record.meta.writerId,
    record.meta.userId,
    client.config.clientId,
    record.meta.type
  )
  if (ak === null) {
    ak = await client.crypto.randomKey()
    await putAccessKey(
      client,
      record.meta.writerId,
      record.meta.userId,
      client.config.clientId,
      record.meta.type,
      ak
    )
  }
  return client.crypto.encryptRecord(record, ak)
}

/**
 * Core client module used to interact with the E3DB API.
 *
 * @property {Config} config E3DB client configuration.
 */
export default class Client extends CryptoConsumer {
  /**
   * Register a new client with a specific account.
   *
   * @param {string}  registrationToken Registration token as presented by the admin console
   * @param {string}  clientName        Distinguishable name to be used for the token in the console
   * @param {KeyPair} cryptoKeys        Curve25519 keypair used for encryption
   * @param {KeyPair} signingKeys       Ed25519 keypair used for signing
   * @param {bool}    [backup]          Optional flag to automatically back up the newly-created credentials to the account service
   * @param {string}  [apiUrl]          Base URI for the e3DB API
   *
   * @returns {ClientDetails}
   */
  static async register(
    registrationToken,
    clientName,
    cryptoKeys,
    signingKeys,
    backup = false,
    apiUrl = DEFAULT_API_URL
  ) {
    /* eslint-disable camelcase */
    let payload
    if (signingKeys) {
      payload = {
        token: registrationToken,
        client: {
          name: clientName,
          public_key: new PublicKey(cryptoKeys.publicKey),
          signing_key: new SigningKey(signingKeys.publicKey)
        }
      }
    } else {
      payload = {
        token: registrationToken,
        client: {
          name: clientName,
          public_key: new PublicKey(cryptoKeys.publicKey)
        }
      }
    }
    /* eslint-enable */
    let backupClientId = false
    let request = await fetch(apiUrl + '/v1/account/e3db/clients/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })
    let response = await checkStatus(request)
    if (response.headers.has('X-Backup-Client')) {
      backupClientId = response.headers.get('X-Backup-Client')
    }
    let json = await response.json()
    let details = await ClientDetails.decode(json)
    if (backup && backupClientId) {
      if (cryptoKeys.privateKey === null) {
        throw new Error('Cannot back up credentials without a private key!')
      }
      let config = signingKeys
        ? new Config(
            details.clientId,
            details.apiKeyId,
            details.apiSecret,
            cryptoKeys.publicKey,
            cryptoKeys.privateKey,
            apiUrl,
            signingKeys.publicKey,
            signingKeys.privateKey
          )
        : new Config(
            details.clientId,
            details.apiKeyId,
            details.apiSecret,
            cryptoKeys.publicKey,
            cryptoKeys.privateKey,
            apiUrl
          )
      // Using `this` as the constructor creates an instance of the implementing
      // concrete class rather than the interface
      let client = new this(config)
      await client.backup(backupClientId, registrationToken)
    }

    return Promise.resolve(details)
  }

  /**
   * Proxy to generating a new key pair using the crypto module provided.
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  static async generateKeypair() {
    return this.crypto.generateKeypair()
  }

  /**
   * Proxy to generating a new signing key pair using the crypto module provided.
   *
   * @returns {KeyPair} Base64URL-encoded representation of the new keypair
   */
  static async generateSigningKeypair() {
    return this.crypto.generateSigningKeypair()
  }

  /**
   * WriteNote is a static method that encrypts a note and sends it to TozStore,
   * allowing you to supply your own signingKey and encryptionKey pairs.
   *
   * Using this method you are not allowed to provide premium options to TozStore,
   * such as additional views, extended expiration time, etc.
   *
   * @param {object} data  A hashmap of the data to encrypt and store
   * @param {string} recipientEncryptionKey The public encryption key of the reader of this note
   * @param {string} recipientSigningKey The public signing key of the reader of this note
   * @param {KeyPair} signingKeyPair Object that has signing public and private keys
   * @param {KeyPair} encryptionKeyPair Object that has encryption public and private keys
   * @param {object} options json hashmap of a NoteOptions object, minus premium features.
   * @param {string} apiUrl Url of the TozStore api that you want to hit (Default is recommended).
   *
   * @returns {Note} A response from TozStore; the note that has been written.
   */
  static async writeNote(
    data,
    recipientEncryptionKey,
    recipientSigningKey,
    encryptionKeyPair,
    signingKeyPair,
    options,
    apiUrl = DEFAULT_API_URL
  ) {
    let anonAuth = await AuthenticatedRequest.anonymousAuth(
      this.crypto,
      signingKeyPair.publicKey,
      signingKeyPair.privateKey,
      apiUrl
    )

    // Premium options are not extracted
    /* eslint-disable camelcase */
    var decodedOptions = NoteOptions.decode({
      type: options.type,
      plain: options.plain,
      max_views: options.max_views
    })
    /* eslint-enable */
    return this.internalWriteNote(
      anonAuth,
      data,
      recipientEncryptionKey,
      recipientSigningKey,
      encryptionKeyPair,
      signingKeyPair,
      decodedOptions,
      apiUrl
    )
  }

  /**
   * ReadNote is a static method used to read a note,
   * allowing you to supply your own signingKey and encryptionKey pairs.
   *
   * @param {string} noteId  UUID assigned by TozStore, used to identify a note.
   * @param {KeyPair} signingKeyPair Object that has signing public and private keys
   * @param {KeyPair} encryptionKeyPair Object that has encryption public and private keys
   * @param {string} apiUrl Url of the TozStore api that you want to hit (Default is recommended).
   *
   * @returns {Note} A note from TozStore unencrypted with the client's keys.
   */
  static async readNote(
    noteId,
    encryptionKeyPair,
    signingKeyPair,
    apiUrl = DEFAULT_API_URL
  ) {
    let anonAuth = await AuthenticatedRequest.anonymousAuth(
      this.crypto,
      signingKeyPair.publicKey,
      signingKeyPair.privateKey,
      apiUrl
    )
    // Use this to ensure we referencing the implementing class.
    return this.internalReadNote(anonAuth, noteId, encryptionKeyPair, apiUrl)
  }

  /**
   * ReadNoteByName is a static method used to read a note by name,
   * allowing you to supply your own signingKey and encryptionKey pairs.
   *
   * PLEASE NOTE: only notes written by a client, not the static writeNote method,
   * can have a noteName attached.
   *
   * @param {string} noteName  name given to this note with premium features
   * @param {KeyPair} signingKeyPair Object that has signing public and private keys
   * @param {KeyPair} encryptionKeyPair Object that has encryption public and private keys
   * @param {string} apiUrl Url of the TozStore api that you want to hit (Default is recommended).
   *
   * @returns {Note} A note from TozStore unencrypted with the client's keys.
   */
  static async readNoteByName(
    noteName,
    encryptionKeyPair,
    signingKeyPair,
    apiUrl = DEFAULT_API_URL
  ) {
    let anonAuth = await AuthenticatedRequest.anonymousAuth(
      this.crypto,
      signingKeyPair.publicKey,
      signingKeyPair.privateKey,
      apiUrl
    )
    // Use this to ensure we referencing the implementing class.
    return this.internalReadNoteByName(anonAuth, noteName, encryptionKeyPair, apiUrl)
  }

  /**
   * DeleteNote is a static method that deletes a note from TozStore based on the note identifier,
   * allowing you to supply your own signingKey pair.
   *
   * @param {string} noteId  UUID assigned by TozStore, used to identify a note.
   */
  static async deleteNote(noteId, signingKeyPair, apiUrl = DEFAULT_API_URL) {
    let anonAuth = await AuthenticatedRequest.anonymousAuth(
      this.crypto,
      signingKeyPair.publicKey,
      signingKeyPair.privateKey,
      apiUrl
    )
    return this.internalDeleteNote(anonAuth, noteId, apiUrl)
  }

  /*
   * InternalWriteNote is an internal method used by writeNote
   */
  static async internalWriteNote(
    authenticator,
    data,
    recipientEncryptionKey,
    recipientSigningKey,
    encryptionKeyPair,
    signingKeyPair,
    options,
    apiUrl
  ) {
    const accessKey = await this.crypto.randomKey()
    const encryptedAccessKey = await this.crypto.encryptAk(
      encryptionKeyPair.privateKey,
      accessKey,
      recipientEncryptionKey
    )
    let noteData = new NoteData(data)
    let noteKeys = new NoteKeys(
      this.crypto.mode(),
      recipientSigningKey,
      signingKeyPair.publicKey,
      encryptionKeyPair.publicKey,
      encryptedAccessKey
    )
    var signableNote = new NoteInfo(noteData, noteKeys, options)
    let signature = await this.crypto.signDocument(
      signableNote,
      signingKeyPair.privateKey
    )
    var unencryptedNote = new Note(noteData, noteKeys, signature, options)
    let encryptedNote = await this.crypto.encryptNote(unencryptedNote, accessKey)
    let response = await authenticator.tsv1Fetch(
      apiUrl + '/v2/storage/notes',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: encryptedNote.toJson()
      },
      options.clientId
    )
    let storedNoteResp = await checkStatus(response)
    let noteJson = await storedNoteResp.json()
    const decodedServerNote = Note.decode(noteJson)
    return decodedServerNote
  }

  /*
   * InternalReadNote is an internal method used by internalReadNote
   */
  static async internalReadNote(authenticator, noteId, encryptionKeyPair, apiUrl) {
    let request = await authenticator.tsv1Fetch(
      apiUrl + `/v2/storage/notes?note_id=${noteId}`,
      {
        method: 'GET'
      }
    )
    let storedNote = await checkStatus(request)
    const noteJson = await storedNote.json()
    // Use this to ensure we referencing the implementing class.
    return this.decryptNoteJson(
      noteJson,
      encryptionKeyPair.privateKey,
      noteJson.writer_encryption_key,
      noteJson.writer_signing_key
    )
  }

  /*
   * InternalReadNoteByName is an internal method used by readNoteByName
   */
  static async internalReadNoteByName(
    authenticator,
    noteName,
    encryptionKeyPair,
    apiUrl
  ) {
    let request = await authenticator.tsv1Fetch(
      apiUrl + `/v2/storage/notes?id_string=${noteName}`,
      {
        method: 'GET'
      }
    )
    let storedNote = await checkStatus(request)
    const noteJson = await storedNote.json()
    // Use this to ensure we referencing the implementing class.
    return this.decryptNoteJson(
      noteJson,
      encryptionKeyPair.privateKey,
      noteJson.writer_encryption_key,
      noteJson.writer_signing_key
    )
  }

  /*
   * InternalDeleteNote is an internal method used by deleteNote
   */
  static async internalDeleteNote(authenticator, noteId, apiUrl) {
    let deletedNoteResponse = await authenticator.tsv1Fetch(
      apiUrl + `/v2/storage/notes/${noteId}`,
      {
        method: 'DELETE'
      }
    )
    return checkStatus(deletedNoteResponse)
  }

  /*
   * Decrypts and validates a note response from TozStore given the proper keys.
   */
  static async decryptNoteJson(noteJson, privateKey, publicKey, publicSigningKey) {
    const encryptedNote = Note.decode(noteJson)
    const eak = noteJson.encrypted_access_key
    const ak = await this.crypto.decryptNoteEak(privateKey, { eak: eak }, publicKey)
    const decryptedNote = await this.crypto.decryptNote(encryptedNote, ak)

    let signableNote = NoteInfo.signableSubsetFromNote(decryptedNote)
    let signed = new SignedDocument(signableNote, decryptedNote.signature)
    let verify = await this.verify(signed, publicSigningKey)
    if (!verify) {
      throw new Error('Note failed verification')
    }
    return decryptedNote
  }

  constructor(config) {
    super()
    if (!(config instanceof Config)) {
      throw new Error('Config must be a valid Config object')
    }
    this.config = config
    this.authenticator = new AuthenticatedRequest(config, this.crypto)
    this._akCache = {}
  }

  /**
   * Get an access key from the cache if it exists, otherwise decrypt
   * the provided EAK and populate the cache.
   *
   * @param {string}  writerId
   * @param {string}  userId
   * @param {string}  readerId
   * @param {string}  type
   * @param {EAKInfo} eak
   *
   * @returns {Promise<string>}
   */
  async _getCachedAk(writerId, userId, readerId, type, eak) {
    let cacheKey = `${writerId}.${userId}.${type}`
    let ak = this._akCache[cacheKey]

    if (ak === undefined) {
      ak = await this.crypto.decryptEak(this.config.privateKey, eak)
      this._akCache[cacheKey] = ak
    }

    return Promise.resolve(ak)
  }

  /**
   * Get a client's information based on their ID.
   *
   * @param {string} clientId UUID of the client to fetch
   *
   * @returns {Promise<ClientInfo>}
   */
  async getClient(clientId) {
    let request = await this.authenticator.tokenFetch(
      this.config.apiUrl + '/v1/storage/clients/' + clientId,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )

    let response = await checkStatus(request)

    let json = await response.json()
    return ClientInfo.decode(json)
  }

  /**
   * Create a key for the current client as a writer if one does not exist
   * in the cache already. If no access key does exist, create a random one
   * and store it with the server.
   *
   * @param {string} type Record type for this key
   *
   * @returns {Promise<EAKInfo>}
   */
  async createWriterKey(type) {
    let ak = await getAccessKey(
      this,
      this.config.clientId,
      this.config.clientId,
      this.config.clientId,
      type
    )

    if (ak === null) {
      ak = await this.crypto.randomKey()
      await putAccessKey(
        this,
        this.config.clientId,
        this.config.clientId,
        this.config.clientId,
        type,
        ak
      )
    }

    let eak = await this.crypto.encryptAk(
      this.config.privateKey,
      ak,
      this.config.publicKey
    )

    return new EAKInfo(
      eak,
      this.config.clientId,
      this.config.publicKey,
      this.config.clientId,
      this.config.publicSigningKey
    )
  }

  /**
   * Get a key for the current client as the reader of a specific record written by someone else.
   *
   * @param {string} writerId Writer of the record in the database
   * @param {string} userID   Subject of the record in the database
   * @param {string} type     Type of record
   *
   * @returns {Promise<EAKInfo>}
   */
  async getReaderKey(writerId, userId, type) {
    return getEncryptedAccessKey(this, writerId, userId, this.config.clientId, type)
  }

  /**
   * Retrieve information about a client, primarily its UUID and public key,
   * based either on an already-known client ID or a discoverable client
   * email address.
   *
   * @param {string} clientId
   *
   * @returns {Promise<ClientInfo>}
   */
  async clientInfo(clientId) {
    if (EMAIL.test(clientId)) {
      // ID is an email address
      throw new Error('Client discovery by email address is not supported')
    }

    return this.getClient(clientId)
  }

  /**
   * Retrieve the Curve 25519 public key associated with a known client.
   *
   * @param {string} clientId
   *
   * @returns {Promise<PublicKey>}
   */
  async clientKey(clientId) {
    if (clientId === this.clientId) {
      return Promise.resolve(null)
    }

    let info = await this.clientInfo(clientId)
    return Promise.resolve(info.publicKey)
  }

  /**
   * Reads a record from the E3DB system and decrypts it automatically.
   *
   * @param {string} recordId
   * @param {array}  [fields] Optional fields to select on the record
   *
   * @returns {Promise<Record>}
   */
  async read(recordId, fields = null) {
    let path = this.config.apiUrl + '/v1/storage/records/' + recordId

    if (fields !== null) {
      let mapped = []
      for (let field of fields) {
        mapped.push('field=' + field)
      }

      path += '?' + mapped.join('&')
    }

    let request = await this.authenticator.tokenFetch(path, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    let response = await checkStatus(request)
    let json = await response.json()
    let record = await Record.decode(json)
    return decryptRecord(this, record)
  }

  /**
   * Create a new record entry with E3DB.
   *
   * @param {string} type  The content type with which to associate the record.
   * @param {object} data  A hashmap of the data to encrypt and store
   * @param {object} plain Optional hashmap of data to store with the record's meta in plaintext
   *
   * @return {Promise<Record>}
   */
  async write(type, data, plain = {}) {
    // Build the record
    if (data instanceof Object) {
      data = new RecordData(data)
    }
    let meta = new Meta(this.config.clientId, this.config.clientId, type, plain)
    let info = new RecordInfo(meta, data)
    let signature = this.config.version > 1 ? await this.sign(info) : null
    let record = new Record(meta, data, signature)
    let encrypted = await encryptRecord(this, record)
    return this.writeRaw(encrypted)
  }

  /**
   * Write a previously stored encrypted/signed record directly to E3DB.
   *
   * @param {Record} record The fully-constructed record object, as returned by `encrypt()`
   *
   * @return {Promise<Record>}
   */
  async writeRaw(record) {
    if (!(record instanceof Record)) {
      throw new Error('Can only write encrypted/signed records directly to the server!')
    }

    let request = await this.authenticator.tokenFetch(
      this.config.apiUrl + '/v1/storage/records',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: record.stringify()
      }
    )
    let response = await checkStatus(request)
    let json = await response.json()
    let written = await Record.decode(json)
    return decryptRecord(this, written)
  }

  /**
   * Encrypt a plaintext record using the AK wrapped and encrypted for the current
   * client. The key will be cached for future use.
   *
   * @param {string}            type  The content type with which to associate the record.
   * @param {RecordData|object} data  A hashmap of the data to encrypt and store
   * @param {object}            eak   Encrypted access key instance
   * @param {object}            plain Optional hashmap of data to store with the record's meta in plaintext
   *
   * @returns {Promise<Record>}
   */
  async localEncrypt(type, data, eak, plain = {}) {
    let ak = await this._getCachedAk(
      this.config.clientId,
      this.config.clientId,
      this.config.clientId,
      type,
      eak
    )

    if (data instanceof Object) {
      data = new RecordData(data)
    }

    // Build the record
    let meta = new Meta(this.config.clientId, this.config.clientId, type, plain)
    let recordInfo = new RecordInfo(meta, data)
    let signature = this.config.version > 1 ? await this.sign(recordInfo) : null
    let record = new Record(meta, data, signature)

    return this.crypto.encryptRecord(record, ak)
  }

  /**
   * Sign a document and return the signature
   *
   * @param {Signable} document Serializable object to be signed.
   *
   * @returns {Promise<string>}
   */
  async sign(document) {
    if (this.config.version === 1) {
      throw new Error('Cannot sign documents without a signing key!')
    }

    return this.crypto.signDocument(document, this.config.privateSigningKey)
  }

  /**
   * Decrypt an encrypted record using the AK wrapped and encrypted for the current
   * client. The key will be cached for future use.
   *
   * @param {Record}  record Record instance with encrypted data for decryption
   * @param {EAKInfo} eak    Encrypted access key instance
   *
   * @returns {Promise<Record>}
   */
  async localDecrypt(record, eak) {
    if (eak.signerSigningKey === null) {
      throw new Error('EAKInfo has no signing key!')
    }

    let ak = await this._getCachedAk(
      record.meta.writerId,
      record.meta.userId,
      this.config.clientId,
      record.meta.type,
      eak
    )

    let decrypted = await this.crypto.decryptRecord(record, ak)
    let info = new RecordInfo(decrypted.meta, decrypted.data)
    let signed = new SignedDocument(info, decrypted.signature)

    // Use this.constructor to ensure the implementing class's crypto is available
    let verify = await this.constructor.verify(signed, eak.signerSigningKey.ed25519)
    if (!verify) {
      throw new Error('Document failed verification')
    }

    return decrypted
  }

  /**
   * Verify the signature attached to a specific document.
   *
   * @param {SignedDocument} signed        Document with an attached signature
   * @param {string}         publicSignKey Key to use during signature verification
   *
   * @returns {Promise<bool>}
   */
  static async verify(signed, publicSignKey) {
    let verified = await this.crypto.verifyDocumentSignature(
      signed.document,
      signed.signature,
      publicSignKey
    )

    return Promise.resolve(verified)
  }

  /**
   * Update a record, with optimistic concurrent locking, that already exists in the E3DB system.
   *
   * @param {Record} record Record to be updated.
   *
   * @returns {Promise<Record>} Updated record
   */
  async update(record) {
    let recordId = record.meta.recordId
    let version = record.meta.version

    // Update record signature
    let recordInfo = new RecordInfo(record.meta, record.data)
    record.signature = this.config.version > 1 ? await this.sign(recordInfo) : null
    let encrypted = await encryptRecord(this, record)
    return this.authenticator
      .tokenFetch(
        this.config.apiUrl + '/v1/storage/records/safe/' + recordId + '/' + version,
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json'
          },
          body: encrypted.stringify()
        }
      )
      .then(checkStatus)
      .then(response => response.json())
      .then(Record.decode)
      .then(rec => {
        return rec
      })
      .then(record => decryptRecord(this, record))
  }

  /**
   * Deletes a record from the E3DB system
   *
   * @param {string} recordId  ID of the record to remove
   * @param {string} [version] Optional version ID to remove safely
   *
   * @returns {Promise<bool>}
   */
  async delete(recordId, version = null) {
    let url = this.config.apiUrl + '/v1/storage/records/' + recordId
    if (version !== null) {
      url = this.config.apiUrl + '/v1/storage/records/safe/' + recordId + '/' + version
    }

    let response = await this.authenticator.tokenFetch(url, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    switch (response.status) {
      case 204:
      case 403:
        return Promise.resolve(true)
      case 409:
        throw new Error('Conflict')
      default:
        throw new Error('Error while deleting record data!')
    }
  }

  /**
   * Back up the client's configuration to E3DB in a serialized format that can be read
   * by the Admin Console. The stored configuration will be shared with the specified client,
   * and the account service notified that the sharing has taken place.
   *
   * @param {string} clientId          Unique ID of the client to which we're backing up
   * @param {string} registrationToken Original registration token used to create the client
   *
   * @returns {Promise<bool>}
   */
  async backup(clientId, registrationToken) {
    /* eslint-disable camelcase */
    let credentials = {
      version: '"' + this.config.version.toString() + '"',
      client_id: '"' + this.config.clientId + '"',
      api_key_id: '"' + this.config.apiKeyId + '"',
      api_secret: '"' + this.config.apiSecret + '"',
      client_email: '""',
      public_key: '"' + this.config.publicKey + '"',
      private_key: '"' + this.config.privateKey + '"'
    }
    if (this.config.version === 2) {
      credentials.public_signing_key = '"' + this.config.publicSigningKey + '"'
      credentials.private_signing_key = '"' + this.config.privateSigningKey + '"'
    }

    credentials.api_url = '"' + this.config.apiUrl + '"'
    /* eslint-enable */
    await this.write('tozny.key_backup', credentials, {
      client: this.config.clientId
    })
    await this.share('tozny.key_backup', clientId)
    await fetch(
      this.config.apiUrl +
        '/v1/account/backup/' +
        registrationToken +
        '/' +
        this.config.clientId,
      {
        method: 'POST'
      }
    )
    return Promise.resolve(true)
  }

  /**
   * Query E3DB records according to a set of selection criteria.
   *
   * The default behavior is to return all records written by the
   * current authenticated client.
   *
   * To restrict the results to a particular type, pass a type or
   * list of types as the `type` argument.
   *
   * To restrict the results to a set of clients, pass a single or
   * list of client IDs as the `writer` argument. To list records
   * written by any client that has shared with the current client,
   * pass the special string 'all' as the `writer` argument.
   *
   * @param {bool}         data     Flag to include data in records
   * @param {string|array} writer   Select records written by a single writer, a list of writers, or 'all'
   * @param {string|array} record   Select a single record or list of records
   * @param {string|array} type     Select records of a single type or a list of types
   * @param {array}        plain    Associative array of plaintext meta to use as a filter
   * @param {number}       pageSize Number of records to fetch per request
   *
   * @returns {QueryResult}
   */
  query(
    data = true,
    writer = null,
    record = null,
    type = null,
    plain = null,
    pageSize = DEFAULT_QUERY_COUNT
  ) {
    let allWriters = false
    if (writer === 'all') {
      allWriters = true
      writer = []
    }

    let query = new Query(
      0,
      data,
      writer,
      record,
      type,
      plain,
      null,
      pageSize,
      allWriters
    )
    return new QueryResult(this, query)
  }

  /**
   * Internal-only method to execute a query against the server and parse the response.
   *
   * @param {Query} query Query request to execute against the server
   *
   * @returns {QueryResult}
   */
  async _query(query) {
    let response = await this.authenticator.tokenFetch(
      this.config.apiUrl + '/v1/storage/search',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: query.stringify()
      }
    )
    await checkStatus(response)
    return response.json()
  }

  /**
   * Grant another E3DB client access to records of a particular type.
   *
   * @param {string} type     Type of records to share
   * @param {string} readerId Client ID or email address of reader to grant access to
   *
   * @returns {Promise<bool>}
   */
  async share(type, readerId) {
    if (readerId === this.config.clientId) {
      return Promise.resolve(true)
    }
    if (EMAIL.test(readerId)) {
      let clientInfo = await this.clientInfo(readerId)
      return this.share(type, clientInfo.clientId)
    }

    let clientId = this.config.clientId
    let ak = await getAccessKey(this, clientId, clientId, clientId, type)
    if (ak === null) {
      ak = await this.crypto.randomKey()
      await putAccessKey(
        this,
        this.config.clientId,
        this.config.clientId,
        this.config.clientId,
        type,
        ak
      )
    }
    await putAccessKey(this, clientId, clientId, readerId, type, ak)
    let policy = { allow: [{ read: {} }] }
    let request = await this.authenticator.tokenFetch(
      this.config.apiUrl +
        '/v1/storage/policy/' +
        clientId +
        '/' +
        clientId +
        '/' +
        readerId +
        '/' +
        type,
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(policy)
      }
    )
    await checkStatus(request)
    return Promise.resolve(true)
  }

  /**
   * Revoke another E3DB client's access to records of a particular type.
   *
   * @param {string} type     Type of records to share
   * @param {string} readerId Client ID or email address of reader to grant access from
   *
   * @returns {Promise<bool>}
   */
  async revoke(type, readerId) {
    if (readerId === this.config.clientId) {
      return Promise.resolve(true)
    }
    if (EMAIL.test(readerId)) {
      let clientInfo = await this.clientInfo(readerId)
      return this.revoke(type, clientInfo.clientId)
    }

    let clientId = this.config.clientId
    let policy = { deny: [{ read: {} }] }
    let request = await this.authenticator.tokenFetch(
      this.config.apiUrl +
        '/v1/storage/policy/' +
        clientId +
        '/' +
        clientId +
        '/' +
        readerId +
        '/' +
        type,
      {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(policy)
      }
    )
    await checkStatus(request)

    // Delete any existing access keys
    await deleteAccessKey(this, clientId, clientId, readerId, type)

    return Promise.resolve(true)
  }

  /**
   * Get a list of all outgoing sharing policy relationships
   *
   * @returns {Promise<array>}
   */
  async outgoingSharing() {
    let request = await this.authenticator.tokenFetch(
      this.config.apiUrl + '/v1/storage/policy/outgoing',
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    let response = await checkStatus(request)
    let json = await response.json()

    return Promise.all(json.map(OutgoingSharingPolicy.decode))
  }

  /**
   * Get a list of all incoming sharing policy relationships
   *
   * @returns {Promise<array>}
   */
  async incomingSharing() {
    let request = await this.authenticator.tokenFetch(
      this.config.apiUrl + '/v1/storage/policy/incoming',
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    let response = await checkStatus(request)
    let json = await response.json()

    return Promise.all(json.map(IncomingSharingPolicy.decode))
  }

  async writeLargeFile(recordType, fileObject, plainMetadata = {}) {
    const clientId = this.config.clientId
    let ak = await getAccessKey(this, clientId, clientId, clientId, recordType)
    if (ak === null) {
      ak = await this.crypto.randomKey()
      await putAccessKey(this, clientId, clientId, clientId, recordType, ak)
    }
    const [encryptedFile, checkSum, encryptedLength] = await this.crypto.encryptLargeFile(
      fileObject,
      ak,
      plainMetadata
    )
    const fileCompression = 'raw'
    const fileObj = new File(
      checkSum,
      fileCompression,
      encryptedLength,
      this.config.clientId,
      this.config.clientId,
      recordType,
      plainMetadata
    )
    const postBody = fileObj.toJson()
    // Post file meta to request AWS S3 Bucket URL.
    const postRequest = await this.authenticator.tokenFetch(
      this.config.apiUrl + '/v1/storage/files',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(postBody)
      }
    )
    const postResponse = await checkStatus(postRequest)
    const postJson = await postResponse.json()
    fileObj.fileUrl = postJson.file_url
    fileObj.recordId = postJson.id
    // Upload encrypted file to AWS S3 Bucket.
    const putRequest = await fetch(fileObj.fileUrl, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-MD5': checkSum
      },
      body: encryptedFile
    })
    await checkStatus(putRequest)
    const patchRequest = await this.authenticator.tokenFetch(
      this.config.apiUrl + `/v1/storage/files/${fileObj.recordId}`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    const patchResponse = await checkStatus(patchRequest)
    const patchJson = await patchResponse.json()
    // Delete the temporary file, here encryptedFile.
    return new File(
      patchJson.meta.file_meta.checksum,
      patchJson.meta.file_meta.compression,
      patchJson.meta.file_meta.size,
      patchJson.meta.writer_id,
      patchJson.meta.user_id,
      patchJson.meta.type,
      patchJson.meta.plain,
      patchJson.meta.file_meta.file_url,
      patchJson.meta.file_meta.file_name,
      patchJson.meta.record_id,
      patchJson.meta.created,
      patchJson.meta.last_modified,
      patchJson.meta.version
    )
  }

  // The file_url appears to be null.  Is that right?

  async readLargeFile(recordId, destinationFilename) {
    /*
    Retrieve an Encrypted file from the server based on recordId.
    Decrypt the file.
    Store the plaintext file in destination_filename.
    */

    // Get TozStore recordId.
    let getRequest = await this.authenticator.tokenFetch(
      this.config.apiUrl + `/v1/storage/files/${recordId}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      }
    )
    let getResponse = await checkStatus(getRequest)
    let getJson = await getResponse.json()
    // Create File instance.
    const fileObj = new File(
      getJson.meta.file_meta.checksum,
      getJson.meta.file_meta.compression,
      getJson.meta.file_meta.size,
      getJson.meta.writer_id,
      getJson.meta.user_id,
      getJson.meta.type,
      getJson.meta.plain,
      getJson.meta.file_meta.file_url,
      getJson.meta.file_meta.file_name,
      getJson.meta.record_id,
      getJson.meta.created,
      getJson.meta.last_modified,
      getJson.meta.version
    )
    // Get the access key to decrypt the record.
    const ak = await getAccessKey(
      this,
      fileObj.writerId,
      this.config.clientId,
      fileObj.writerId,
      fileObj.recordType
    )
    if (ak === null) {
      throw new Error(`Can't read records of type ${fileObj.type}`)
    }
    // How to upload / fetch the file stream efficiently?
    const fileRequest = await fetch(fileObj.fileUrl, {
      method: 'GET'
    })
    let fileResponse = await checkStatus(fileRequest)
    let encryptedFileArrayBuffer = await fileResponse.arrayBuffer()
    // Should take the encryptedFileName and destinationFileName
    const fileName = destinationFilename
      ? destinationFilename
      : getJson.meta.file_meta.file_name
    const decrypted = await this.crypto.decryptFile(
      fileName,
      ak,
      encryptedFileArrayBuffer
    )
    // Delete the encrypted file.  No longer needed.
    // File not yet added to any file system.
    // Returned with the File object.
    return [decrypted, fileObj]
  }

  /**
   * WriteNote is a static method that encrypts a note and sends it to TozStore,
   * allowing you to supply your own signingKey and encryptionKey pairs.
   *
   * Using this method you are not allowed to provide premium options to TozStore,
   * such as additional views, extended expiration time, etc.
   *
   * @param {object} data  A hashmap of the data to encrypt and store
   * @param {string} recipientEncryptionKey The public encryption key of the reader of this note
   * @param {string} recipientSigningKey signing key of the reader of this note
   * @param {object} options json hashmap of a NoteOptions object.
   *
   * @returns {Note} A response from TozStore; the note that has been written.
   */
  async writeNote(data, recipientEncryptionKey, recipientSigningKey, options) {
    // Automatically mix in the client id unless it is overridden in the provided options.
    /* eslint-disable camelcase */
    const decodedOptions = NoteOptions.decode(
      Object.assign({ client_id: this.config.clientId }, options)
    )
    /* eslint-enable */
    const encryptionKeys = new KeyPair(this.config.publicKey, this.config.privateKey)
    let signingKeys = new KeyPair(
      this.config.publicSigningKey,
      this.config.privateSigningKey
    )
    return this.constructor.internalWriteNote(
      this.authenticator,
      data,
      recipientEncryptionKey,
      recipientSigningKey,
      encryptionKeys,
      signingKeys,
      decodedOptions,
      this.config.apiUrl
    )
  }

  /**
   * ReadNote makes call to TozStore to read note by noteId (uuid).
   *
   * @param {string} noteId  UUID assigned by TozStore, used to identify a note.
   *
   * @returns {Note} A note from TozStore unencrypted with the client's keys.
   */
  async readNote(noteId) {
    if (this.config.version === 1) {
      throw new Error('Cannot read notes without a signing key!')
    }
    let encryptionKeys = new KeyPair(this.config.publicKey, this.config.privateKey)
    // Use this.constructor to ensure we referencing the implementing class.
    return this.constructor.internalReadNote(
      this.authenticator,
      noteId,
      encryptionKeys,
      this.config.apiUrl
    )
  }

  /**
   * ReadNoteByName makes call to TozStore to read note by user defined id_string.
   * Only premium notes can define this id string or name.
   *
   * @param {string} noteName  name given to this note with premium features
   *
   * @returns {Note} A note from TozStore unencrypted with the client's keys.
   */
  async readNoteByName(noteName) {
    if (this.config.version === 1) {
      throw new Error('Cannot read notes without a signing key!')
    }
    let encryptionKeys = new KeyPair(this.config.publicKey, this.config.privateKey)
    // Use this.constructor to ensure we referencing the implementing class.
    return this.constructor.internalReadNoteByName(
      this.authenticator,
      noteName,
      encryptionKeys,
      this.config.apiUrl
    )
  }

  /**
   * DeleteNote deletes a note from TozStore based on the note identifier.
   *
   * @param {string} noteId  UUID assigned by TozStore, used to identify a note.
   */
  async deleteNote(noteId) {
    if (this.config.version === 1) {
      throw new Error('Cannot delete notes without a signing key!')
    }
    // Use this.constructor to ensure we referencing the implementing class.
    return this.constructor.internalDeleteNote(
      this.authenticator,
      noteId,
      this.config.apiUrl
    )
  }
}
