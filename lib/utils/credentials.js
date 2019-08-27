import { IDENTITY_DERIVATION_ROUNDS } from './constants'

export async function deriveNoteCreds(idConfig, crypto, username, password) {
  console.log(
    `[deriveNoteCreds] attempting to derive note creds params ${idConfig}, ${crypto}, ${username}, ${password}`
  )
  const noteID = await crypto.genericHash(username + idConfig.realmId)
  console.log(`[deriveNoteCreds] after hashed note id ${noteID}`)
  const cryptoKeyPair = await crypto.deriveCryptoKey(
    password,
    idConfig.realmId + idConfig.realmName,
    IDENTITY_DERIVATION_ROUNDS
  )
  console.log(`[deriveNoteCreds] after cryptokeypair ${cryptoKeyPair}`)
  const signingKeyPair = await crypto.deriveSigningKey(
    password,
    cryptoKeyPair.publicKey + cryptoKeyPair.privateKey,
    IDENTITY_DERIVATION_ROUNDS
  )
  console.log(`[deriveNoteCreds] after signingKeyPair ${signingKeyPair}`)
  return { noteID, cryptoKeyPair, signingKeyPair }
}
