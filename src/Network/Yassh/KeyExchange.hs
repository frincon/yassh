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
{-# LANGUAGE ExistentialQuantification #-}

module Network.Yassh.KeyExchange
  ( runKeyExchange
  ) where

import Control.Monad (void, when)
import Crypto.Hash
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Either (either)
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy(Proxy))
import Data.Word8 (Word8)
import Development.Placeholders
import Network.Yassh.Internal
import Network.Yassh.Internal.KeyExchange
import Network.Yassh.Internal.KeyExchange.DiffieHellman --TODO This should not be here

data SshPacketKexInit = SshPacketKexInit
  { kexInitCookie :: Cookie
  , kexInitKexSet :: KexSet
  , kexInitFirstKexPacketFollow :: Bool
  } deriving (Show)

instance ToSshPacket SshPacketKexInit where
  toSshPacket SshPacketKexInit { kexInitCookie = (MkCookie cookieBytes)
                               , kexInitKexSet = kexSet
                               , kexInitFirstKexPacketFollow = firstKexPacketFollows
                               } =
    SshPacket
      c_SSH_MSG_KEXINIT
      [ SshByteArray 16 cookieBytes
      , SshNameList $ nameAsBytestring <$> kexAlgorithms kexSet
      , SshNameList $ nameAsBytestring <$> serverHostKeyAlgorithms kexSet
      , SshNameList $ nameAsBytestring <$> encryptionAlgorithmsClientToServer kexSet
      , SshNameList $ nameAsBytestring <$> encryptionAlgorithmsServerToClient kexSet
      , SshNameList $ nameAsBytestring <$> macAlgorithmsClientToServer kexSet
      , SshNameList $ nameAsBytestring <$> macAlgorithmsServerToClient kexSet
      , SshNameList $ nameAsBytestring <$> compressionAlgorithmsClientToServer kexSet
      , SshNameList $ nameAsBytestring <$> compressionAlgorithmsServerToClient kexSet
      , SshNameList $ nameAsBytestring <$> languagesClientToServer kexSet
      , SshNameList $ nameAsBytestring <$> languagesServerToClient kexSet
      , SshBoolean firstKexPacketFollows
      , SshUInt32 0 -- Future use
      ]
    where
      extractNameList f = f kexSet

instance FromSshRawPacket SshPacketKexInit where
  fromSshRawPacket (SshRawPacket _ payload) = runGet readKexPacket $ LBS.fromStrict payload
  expectedMsgId _ = c_SSH_MSG_KEXINIT

runKeyExchange :: SshRole -> SshClientServer SshVersion -> ([Word8] -> IO SshRawPacket) -> (SshPacket -> IO ()) -> IO ()
runKeyExchange role versions recv send
    -- TODO Remove this from here
 = do
  (publicHostKey, privateHostKey) <- generate 256 65537
  print publicHostKey
    -- End
  putStrLn "Running key exchange"
  let kexInitRawPacketSent = toSshRawPacket $ toSshPacket kexInitPacket
  send $ toSshPacket kexInitPacket
  putStrLn "SSH_MSG_KEXINIT Sent"
  kexInitRawPacketReceived <- recv [c_SSH_MSG_KEXINIT]
  let kexInitReceived = fromSshRawPacket kexInitRawPacketReceived
  putStrLn "SSH_MSG_KEXINIT Received"
  when
    (kexInitFirstKexPacketFollow kexInitReceived && guessIsWrong (kexInitKexSet kexInitReceived) supportedKexSet)
    (void $ recv [30 .. 49]) -- Discard the next packet
  let result = algorithmNegotiation $ fromRole role supportedKexSet (kexInitKexSet kexInitReceived)
  putStrLn $ "Received: " ++ show kexInitReceived
  putStrLn $ "Negotiated: " ++ show result
  let kexContext =
        KexContext
        { kexContextIdentificationString = fmap toIdentificationString versions
        , kexContextMsgInit = fromRole role kexInitRawPacketSent kexInitRawPacketReceived
        , kexContextHostKeyAlgorithm = negotiatedServerHostKeyAlgorithm result
        , kexContextHostKeyEncoded = encodeRsaPubKey publicHostKey
        , kexContextSign =
            \toSign ->
              sshRawPacketPayload $
              toSshRawPacket $
              SshPacket
                0
                [SshString "ssh-rsa", SshString $ either (error . show) id $ sign Nothing (Just SHA1) privateHostKey toSign]
        }
  (runKex $ negotiatedKexAlgorithm result) role kexContext recv send
  where
    guessIsWrong :: KexSet -> KexSet -> Bool
    guessIsWrong received sent =
      (head (kexAlgorithms received) /= head (kexAlgorithms sent)) ||
      (head (serverHostKeyAlgorithms received) /= head (serverHostKeyAlgorithms sent))
    encodeRsaPubKey (PublicKey _ n e) =
      sshRawPacketPayload $ toSshRawPacket $ SshPacket 0 [SshString "ssh-rsa", SshMPint e, SshMPint n]

kexInitPacket :: SshPacketKexInit
kexInitPacket = SshPacketKexInit newCookie supportedKexSet False

data KexSet = KexSet
  { kexAlgorithms :: [KexAlgorithm]
  , serverHostKeyAlgorithms :: [HostKeyAlgorithm]
  , encryptionAlgorithmsClientToServer :: [EncryptionAlgorithm]
  , encryptionAlgorithmsServerToClient :: [EncryptionAlgorithm]
  , macAlgorithmsClientToServer :: [MacAlgorithm]
  , macAlgorithmsServerToClient :: [MacAlgorithm]
  , compressionAlgorithmsClientToServer :: [CompressionAlgorithm]
  , compressionAlgorithmsServerToClient :: [CompressionAlgorithm]
  , languagesClientToServer :: [Language]
  , languagesServerToClient :: [Language]
  } deriving (Show)

data NegotiatedAlgorithms = NegotiatedAlgorithms
  { negotiatedKexAlgorithm :: KexAlgorithm
  , negotiatedServerHostKeyAlgorithm :: HostKeyAlgorithm
  , negotiatedEncryptionAlgorithmClientToServer :: EncryptionAlgorithm
  , negotiatedEncryptionAlgorithmServerToClient :: EncryptionAlgorithm
  , negotiatedMacAlgorithmClientToServer :: MacAlgorithm
  , negotiatedMacAlgorithmServerToClient :: MacAlgorithm
  , negotiatedCompressionAlgorithmClientToServer :: CompressionAlgorithm
  , negotiatedCompressionAlgorithmServerToClient :: CompressionAlgorithm
  , negotiatedLanguageClientToServer :: Maybe Language
  , negotiatedLanguageServerToClient :: Maybe Language
  } deriving (Show)

newtype Cookie =
  MkCookie ByteString
  deriving (Show)

newCookie :: Cookie
newCookie = MkCookie $ BS.replicate 16 55 -- TODO make random

algorithmNegotiation :: SshClientServer KexSet -> NegotiatedAlgorithms
algorithmNegotiation ksClientServer =
  NegotiatedAlgorithms
  { negotiatedKexAlgorithm = negotiateKexAlgorithm ksClientServer
  , negotiatedServerHostKeyAlgorithm = negotiateHostKeyAlgorithm ksClientServer
  , negotiatedEncryptionAlgorithmClientToServer =
      negotiateClientMatch encryptionAlgorithmsClientToServer "No client to server encryption algorithm" ksClientServer
  , negotiatedEncryptionAlgorithmServerToClient =
      negotiateClientMatch encryptionAlgorithmsServerToClient "No server to client encryption algorithm" ksClientServer
  , negotiatedMacAlgorithmClientToServer =
      negotiateClientMatch macAlgorithmsClientToServer "No client to server mac algorithm" ksClientServer
  , negotiatedMacAlgorithmServerToClient =
      negotiateClientMatch macAlgorithmsServerToClient "No server to client mac algorithm" ksClientServer
  , negotiatedCompressionAlgorithmClientToServer =
      negotiateClientMatch compressionAlgorithmsClientToServer "No client to server compression algorithm" ksClientServer
  , negotiatedCompressionAlgorithmServerToClient =
      negotiateClientMatch compressionAlgorithmsServerToClient "No server to client compression algorithm" ksClientServer
  , negotiatedLanguageClientToServer = Nothing
  , negotiatedLanguageServerToClient = Nothing
  }

-- TODO Check whether the algorithm and the host key needs signature-capable and encryption-cappable
negotiateKexAlgorithm :: SshClientServer KexSet -> KexAlgorithm
negotiateKexAlgorithm ksClientServer =
  if head (kexAlgorithms $ clientData ksClientServer) == head (kexAlgorithms $ serverData ksClientServer) -- The guess
    then head $ kexAlgorithms $ clientData ksClientServer
    else negotiateClientMatch kexAlgorithms "No key exchange algorithm" ksClientServer

-- TODO Check whether the algorithm and the host key needs signature-capable and encryption-cappable
negotiateHostKeyAlgorithm :: SshClientServer KexSet -> HostKeyAlgorithm
negotiateHostKeyAlgorithm = negotiateClientMatch serverHostKeyAlgorithms "No hostkey algorithms"

negotiateClientMatch :: Eq a => (KexSet -> [a]) -> String -> SshClientServer KexSet -> a
negotiateClientMatch conversion errorMsg SshClientServer {clientData = client, serverData = server} =
  fromMaybe (error errorMsg) (findFirst (conversion client) (conversion server))

findFirst :: Eq a => [a] -> [a] -> Maybe a
findFirst [] _ = Nothing
findFirst (x:xs) other =
  if x `elem` other
    then Just x
    else findFirst xs other

supportedKexAlgorithms = [findKexAlgorithm "diffie-hellman-group1-sha1", findKexAlgorithm "diffie-hellman-group14-sha1"]

supportedKeyAlgorithms = [HostKeyAlgorithm "ssh-dss" True True, HostKeyAlgorithm "ssh-rsa" True True]

supportedEncryptionAlgorithms = [EncryptionAlgorithm "aes128-ctr", EncryptionAlgorithm "3des-cbc"]

supportedMacAlgorithms = [MacAlgorithm "hmac-sha1"]

supportedCompressionAlgorithms = [CompressionAlgorithm "none"]

supportedLanguages = []

supportedKexSet =
  KexSet
  { kexAlgorithms = supportedKexAlgorithms
  , serverHostKeyAlgorithms = supportedKeyAlgorithms
  , encryptionAlgorithmsClientToServer = supportedEncryptionAlgorithms
  , encryptionAlgorithmsServerToClient = supportedEncryptionAlgorithms
  , macAlgorithmsClientToServer = supportedMacAlgorithms
  , macAlgorithmsServerToClient = supportedMacAlgorithms
  , compressionAlgorithmsClientToServer = supportedCompressionAlgorithms
  , compressionAlgorithmsServerToClient = supportedCompressionAlgorithms
  , languagesClientToServer = supportedLanguages
  , languagesServerToClient = supportedLanguages
  }

readKexPacket :: Get SshPacketKexInit
readKexPacket = do
  cookie <- fmap MkCookie (getByteString 16)
  kexSet <-
    KexSet <$> getNameList findKexAlgorithm <*> getNameList findHostKeyAlgorithm <*> getNameList EncryptionAlgorithm <*>
    getNameList EncryptionAlgorithm <*>
    getNameList MacAlgorithm <*>
    getNameList MacAlgorithm <*>
    getNameList CompressionAlgorithm <*>
    getNameList CompressionAlgorithm <*>
    getNameList Language <*>
    getNameList Language
  firstKexPacketFollows <- getBoolean
  getInt32be -- the last uint32
  return $ SshPacketKexInit cookie kexSet firstKexPacketFollows

getNameList :: (ByteString -> a) -> Get [a]
getNameList conversion = do
  nameListLength <- fmap fromIntegral getWord32be
  listWithCommas <- getByteString nameListLength
  return $ conversion <$> C8.split ',' listWithCommas

getBoolean :: Get Bool
getBoolean = do
  value <- getWord8
  if value == 0
    then return False
    else return True

knownKexAlgorithms :: [(ByteString, KexAlgorithm)]
knownKexAlgorithms =
  [ (kexAlgorithmName diffieHellmanGroup1Sha1, diffieHellmanGroup1Sha1)
  , (kexAlgorithmName diffieHellmanGroup14Sha1, diffieHellmanGroup14Sha1)
  ]
  where
    buildEntry key req1 req2 req3 = (key, KexAlgorithm key req1 req2 req3)

findKexAlgorithm key = fromMaybe (KexAlgorithm key True True undefined) (lookup key knownKexAlgorithms)

knownHostKeyAlgorithms :: [(ByteString, HostKeyAlgorithm)]
knownHostKeyAlgorithms = [buildEntry "ssh-dss" True True, buildEntry "ssh-rsa" True True]
  where
    buildEntry key req1 req2 = (key, HostKeyAlgorithm key req1 req2)

findHostKeyAlgorithm key = fromMaybe (HostKeyAlgorithm key False False) (lookup key knownHostKeyAlgorithms)
