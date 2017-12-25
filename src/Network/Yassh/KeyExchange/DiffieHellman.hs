-- Copyright 2017 Fernando Rincon Martin
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.Yassh.KeyExchange.DiffieHellman
  ( diffieHellmanGroup1Sha1
  , diffieHellmanGroup14Sha1
  ) where

import Control.Concurrent.Async (concurrently)
import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.PubKey.DH
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.ByteArray (ByteArray, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Proxy (Proxy(Proxy))
import Data.Word (Word8)
import Development.Placeholders
import Network.Yassh.Internal
import Network.Yassh.Internal.KeyExchange

data SshPacketKexdhInit = SshPacketKexdhInit
  { kexdhInitClientValue :: PublicNumber
  }

data SshPacketKexdhReply = SshPacketKexdhReply
  { kexdhReplyHostKey :: ByteString
  , kexdhReplyServerValue :: PublicNumber
  , kexdhReplySignatureExchangeHash :: ByteString
  }

instance FromSshRawPacket SshPacketKexdhInit where
  fromSshRawPacket (SshRawPacket _ payload) = runGet readKexdhInitPacket $ LBS.fromStrict payload
  expectedMsgId _ = c_SSH_MSG_KEXDH_INIT

instance ToSshPacket SshPacketKexdhReply where
  toSshPacket SshPacketKexdhReply { kexdhReplyHostKey = hostKey
                                  , kexdhReplyServerValue = (PublicNumber serverValue)
                                  , kexdhReplySignatureExchangeHash = signature
                                  } = SshPacket c_SSH_MSG_KEXDH_REPLY [SshString hostKey, SshMPint serverValue, SshString signature]

data DiffieHellmanKexAlgorithm h = MkDiffieHellmanKexAlgorithm
  { dhParams :: Params
  , hashAlgorithm :: h
  , dhAlgorithmName :: ByteString
  }

createDiffieHellmanAlgorithm :: HashAlgorithm h => DiffieHellmanKexAlgorithm h -> KexAlgorithm
createDiffieHellmanAlgorithm dhAlg =
  KexAlgorithm
  { kexAlgorithmName = dhAlgorithmName dhAlg
  , requiresEncryptionCapable = False
  , requiresSignatureCapable = True
  , runKex = runDh dhAlg
  , Network.Yassh.Internal.KeyExchange.hash = dhHash dhAlg
  }

dhHash :: HashAlgorithm h => DiffieHellmanKexAlgorithm h -> ByteString -> ByteString
dhHash dhAlg = convert . callHash dhAlg
  where
    callHash :: HashAlgorithm h => DiffieHellmanKexAlgorithm h -> ByteString -> Digest h
    callHash _ = Crypto.Hash.hash

diffieHellmanGroup1Sha1 :: KexAlgorithm
diffieHellmanGroup1Sha1 = createDiffieHellmanAlgorithm $ MkDiffieHellmanKexAlgorithm params SHA1 "diffie-hellman-group1-sha1"
  where
    params = Params {params_p = prime, params_g = generator, params_bits = bits}
    bits = 1024
    generator = 2
    prime =
      0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

diffieHellmanGroup14Sha1 :: KexAlgorithm
diffieHellmanGroup14Sha1 = createDiffieHellmanAlgorithm $ MkDiffieHellmanKexAlgorithm params SHA1 "diffie-hellman-group14-sha1"
  where
    params = Params {params_p = prime, params_g = generator, params_bits = bits}
    bits = 2048
    generator = 2
    prime =
      0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

runDh ::
     HashAlgorithm h
  => DiffieHellmanKexAlgorithm h
  -> SshRole
  -> KexContext
  -> ([Word8] -> IO SshRawPacket)
  -> (SshPacket -> IO ())
  -> IO KexResult
runDh dhAlg role = roleBased role (runDhServer dhAlg) (runDhClient dhAlg)

runDhServer ::
     HashAlgorithm h
  => DiffieHellmanKexAlgorithm h
  -> KexContext
  -> ([Word8] -> IO SshRawPacket)
  -> (SshPacket -> IO ())
  -> IO KexResult
runDhServer dhAlg@(MkDiffieHellmanKexAlgorithm params _ _) context recv send = do
  otherPartyPublicNumber <- kexdhInitClientValue <$> recvKexdhInit
  privateNumber <- generatePrivate params
  let publicNumber = calculatePublic params privateNumber
  let sharedKey = getShared params privateNumber otherPartyPublicNumber
  let exchangeHash = calculateExchangeHash otherPartyPublicNumber publicNumber sharedKey
  let signature = kexContextSign context exchangeHash
  send $ toSshPacket $ SshPacketKexdhReply (kexContextHostKeyEncoded context) publicNumber signature
  return KexResult {kexResultExchangeHash = convert exchangeHash, kexResultSharedKey = convert sharedKey}
  where
    recvKexdhInit :: IO SshPacketKexdhInit
    recvKexdhInit = fromSshRawPacket <$> recv [c_SSH_MSG_KEXDH_INIT]
    extractInteger (PublicNumber i) = i
    toExchangeString :: PublicNumber -> PublicNumber -> SharedKey -> ByteString
    toExchangeString otherPartyPublicNumber publicNumber sharedKey =
      sshEncode
        [ SshString $ clientData $ kexContextIdentificationString context
        , SshString $ serverData $ kexContextIdentificationString context
        , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ clientData $ kexContextMsgInit context)
        , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ serverData $ kexContextMsgInit context)
        , SshString $ kexContextHostKeyEncoded context
        , SshMPint $ extractInteger otherPartyPublicNumber
        , SshMPint $ extractInteger publicNumber
        , SshMPint $ os2ip sharedKey
        ]
    calculateExchangeHash :: PublicNumber -> PublicNumber -> SharedKey -> ByteString
    calculateExchangeHash a b c = dhHash dhAlg $ toExchangeString a b c

runDhClient ::
     HashAlgorithm h
  => DiffieHellmanKexAlgorithm h
  -> KexContext
  -> ([Word8] -> IO SshRawPacket)
  -> (SshPacket -> IO ())
  -> IO KexResult
runDhClient = $notImplemented

readKexdhInitPacket :: Get SshPacketKexdhInit
readKexdhInitPacket = SshPacketKexdhInit <$> fmap PublicNumber getMPint
