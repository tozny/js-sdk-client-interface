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
 * Root types
 */
import { default as Client } from './client'
import { default as Config } from './config'
import { default as Crypto } from './crypto'
const ClientInterface = {
  Client,
  Config,
  Crypto
}

export default ClientInterface

/**
 * Primitive types
 */
import { default as ClientDetails } from './types/clientDetails'
import { default as ClientInfo } from './types/clientInfo'
import { default as EAKInfo } from './types/eakInfo'
import { default as File } from './types/file'
import { default as IncomingSharingPolicy } from './types/incomingSharingPolicy'
import { default as KeyPair } from './types/keyPair'
import { default as Meta } from './types/meta'
import { default as OutgoingSharingPolicy } from './types/outgoingSharingPolicy'
import { default as PublicKey } from './types/publicKey'
import { default as Query } from './types/query'
import { default as QueryResult } from './types/queryResult'
import { default as Record } from './types/record'
import { default as RecordData } from './types/recordData'
import { default as RecordInfo } from './types/recordInfo'
import { default as Serializable } from './types/serializable'
import { default as Signable } from './types/signable'
import { default as SignedDocument } from './types/signedDocument'
import { default as SignedString } from './types/signedString'
import { default as SigningKey } from './types/signingKey'
import { default as Auth } from './auth'

export const types = {
  ClientDetails,
  ClientInfo,
  EAKInfo,
  File,
  IncomingSharingPolicy,
  KeyPair,
  Meta,
  OutgoingSharingPolicy,
  PublicKey,
  Query,
  QueryResult,
  Record,
  RecordData,
  RecordInfo,
  Serializable,
  Signable,
  SignedDocument,
  SignedString,
  SigningKey,
  Auth
}
