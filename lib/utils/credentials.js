import { IDENTITY_DERIVATION_ROUNDS } from './constants'

/**
 * Derive the note name, crypto, and signing keys for an note containing identity credentials.
 *
 * @param {Config} idConfig The identity realm configuration.
 * @param {Crypto} crypto The concrete Tozny crypto implementation.
 * @param {string} username The username credentials are being derived for.
 * @param {*} password The secret password for the user.
 * @param {*} credType The type of derived credentials for the note, options are `password`, `email_otp`, and `tozny_otp`.
 */
export async function deriveNoteCreds(
  idConfig,
  crypto,
  username,
  password,
  credType = 'password'
) {
  let nameSeed = `${username}@realm:${idConfig.realmName}`
  switch (credType) {
    case 'email_otp':
      nameSeed = `broker:${nameSeed}`
      break
    case 'tozny_otp':
      nameSeed = `tozny_otp:${nameSeed}`
      break
    case 'password':
      break
    default:
      throw new Error(`An invalid credential type was provided ${credType}`)
  }
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
