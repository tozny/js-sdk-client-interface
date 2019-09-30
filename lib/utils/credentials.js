import { IDENTITY_DERIVATION_ROUNDS } from './constants'

/**
 * Derive the note name, crypto, and signing keys for an note containing identity credentials.
 *
 * @param {Config} idConfig The identity realm configuration.
 * @param {Crypto} crypto The concrete Tozny crypto implementation.
 * @param {string} username The username credentials are being derived for.
 * @param {*} password The secret password for the user.
 * @param {*} broker Whether the credentials are for a brokered note.
 */
export async function deriveNoteCreds(
  idConfig,
  crypto,
  username,
  password,
  broker = false
) {
  const nameSeed = broker
    ? `broker:${username}@realm:${idConfig.realmName}`
    : `${username}@realm:${idConfig.realmName}`
  const noteID = await crypto.genericHash(nameSeed)
  const cryptoKeyPair = await crypto.deriveCryptoKey(
    password,
    nameSeed,
    IDENTITY_DERIVATION_ROUNDS
  )
  const signingKeyPair = await crypto.deriveSigningKey(
    password,
    cryptoKeyPair.publicKey + cryptoKeyPair.privateKey,
    IDENTITY_DERIVATION_ROUNDS
  )
  return { noteID, cryptoKeyPair, signingKeyPair }
}
