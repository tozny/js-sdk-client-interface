import { IDENTITY_DERIVATION_ROUNDS } from './constants'

export async function deriveNoteCreds(
  idConfig,
  crypto,
  username,
  password,
  broker = false
) {
  const nameSeed = broker
    ? `broker${username}${idConfig.realmId}`
    : `${username}${idConfig.realmId}`
  const noteID = await crypto.genericHash(nameSeed)
  const cryptoKeyPair = await crypto.deriveCryptoKey(
    password,
    idConfig.realmId + idConfig.realmName,
    IDENTITY_DERIVATION_ROUNDS
  )
  const signingKeyPair = await crypto.deriveSigningKey(
    password,
    cryptoKeyPair.publicKey + cryptoKeyPair.privateKey,
    IDENTITY_DERIVATION_ROUNDS
  )
  return { noteID, cryptoKeyPair, signingKeyPair }
}
