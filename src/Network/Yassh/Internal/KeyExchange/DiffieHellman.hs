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
module Network.Yassh.Internal.KeyExchange.DiffieHellman
( diffieHellmanGroup1Sha1
, diffieHellmanGroup14Sha1
, group14params
)
where

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.PubKey.DH
import Data.Binary.Get
        (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromJust)
import Data.Proxy (Proxy(Proxy))
import Data.Word (Word8)
import Development.Placeholders
import qualified Network.Yassh.HostKey as HostKey
import Network.Yassh.Internal
import Network.Yassh.KeyExchange
  
group14params =
  Params 
    { params_p = safeReadHex
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
        \020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
        \4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
        \EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
        \98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
        \9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
        \E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
        \3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
    , params_g = 2
    , params_bits = 2048
    }

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

diffieHellmanGroup1Sha1 :: ServerHandle
diffieHellmanGroup1Sha1 =
  ServerHandle
  { name = "diffie-hellman-group1-sha1"
  , requiresHostKeyEncryptionCapable = False
  , requiresHostKeySignatureCapable = True
  , runKex = $notImplemented
  }

diffieHellmanGroup14Sha1 :: ServerHandle
diffieHellmanGroup14Sha1 =
  ServerHandle
  { name = "diffie-hellman-group14-sha1"
  , requiresHostKeyEncryptionCapable = False
  , requiresHostKeySignatureCapable = True
  , runKex = runDhGroup14Sha1Server
  }

runDhGroup14Sha1Server :: KexServerContext -> ([Word8] -> IO SshRawPacket) -> (SshPacket -> IO ()) -> IO (ByteString, ByteString)
runDhGroup14Sha1Server context recv send = do
  otherPartyPublicNumber <- kexdhInitClientValue <$> recv' (Proxy :: Proxy SshPacketKexdhInit) -- e
  privateNumber <- generatePrivate group14params -- y
  let publicNumber = calculatePublic group14params privateNumber -- f
  let sharedKey = getShared group14params privateNumber otherPartyPublicNumber -- K
  let exchangePacket =
          [ SshString $ clientData $ kexContextIdentificationString context
          , SshString $ serverData $ kexContextIdentificationString context
          , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ clientData $ kexContextMsgInit context)
          , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ serverData $ kexContextMsgInit context)
          , SshString $ sshEncode $ HostKey.encodedKey $ kexContextHostKeyHandle context
          , SshMPint $ extractInteger otherPartyPublicNumber
          , SshMPint $ extractInteger publicNumber
          , SshMPint $ os2ip sharedKey
          ]
  let exchangeString = sshEncode exchangePacket
  let exchangeHash = (convert $ sha1 exchangeString) :: ByteString
  let signature = sshEncode $ fromJust (HostKey.sign (kexContextHostKeyHandle context)) exchangeHash
  send $ toSshPacket $ SshPacketKexdhReply (sshEncode $ HostKey.encodedKey $ kexContextHostKeyHandle context) publicNumber signature
  return (convert sharedKey, exchangeHash)
  where
    recv' :: FromSshRawPacket p => Proxy p -> IO p
    recv' proxy = fromSshRawPacket <$> recv [expectedMsgId proxy]
    extractInteger (PublicNumber i) = i
    sha1 :: ByteString -> Digest SHA1
    sha1 = hash

readKexdhInitPacket :: Get SshPacketKexdhInit
readKexdhInitPacket = SshPacketKexdhInit <$> fmap PublicNumber getMPint
      