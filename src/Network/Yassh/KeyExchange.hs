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

module Network.Yassh.KeyExchange
  ( runKeyExchange
  ) where

import Control.Monad (void)
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromMaybe)
import Data.Word8 (Word8)
import Development.Placeholders
import Network.Yassh.Internal

runKeyExchange :: SshRole -> ([Word8] -> IO SshRawPacket) -> (SshPacket -> IO ()) -> IO ()
runKeyExchange role recv send = do
  putStrLn "Running key exchange"
  send kexInitPacket
  putStrLn "SSH_MSG_KEXINIT Sent"
  received@(cookie, ksReceived, followPacket) <- recv' [c_SSH_MSG_KEXINIT] readKexPacket
  putStrLn "SSH_MSG_KEXINIT Received"
  let result = algorithmNegotiation $ fromRole role supportedKexSet ksReceived
  putStrLn $ "Received: " ++ (show received)
  if followPacket && guessIsWrong ksReceived supportedKexSet
    then void $ recv [30 .. 49] -- Discard the next packet
    else mempty
  return ()
  where
    recv' :: [Word8] -> Get r -> IO r
    recv' accepted reader = do
      SshRawPacket _ payload <- recv accepted
      return $ runGet reader $ LBS.fromStrict payload
    guessIsWrong :: KexSet -> KexSet -> Bool
    guessIsWrong received sent =
      (head (kexAlgorithms received) /= head (kexAlgorithms sent)) ||
      (head (serverHostKeyAlgorithms received) /= head (serverHostKeyAlgorithms sent))

kexInitPacket :: SshPacket
kexInitPacket =
  SshPacket
    c_SSH_MSG_KEXINIT
    [ SshByteArray 16 $ BS.replicate 16 55 -- TODO This is the cookie, should be random
    , SshNameList $ supportedAlgorithm kexAlgorithms
    , SshNameList $ supportedAlgorithm serverHostKeyAlgorithms
    , SshNameList $ supportedAlgorithm encryptionAlgorithmsClientToServer
    , SshNameList $ supportedAlgorithm encryptionAlgorithmsServerToClient
    , SshNameList $ supportedAlgorithm macAlgorithmsClientToServer
    , SshNameList $ supportedAlgorithm macAlgorithmsServerToClient
    , SshNameList $ supportedAlgorithm compressionAlgorithmsClientToServer
    , SshNameList $ supportedAlgorithm compressionAlgorithmsServerToClient
    , SshNameList $ supportedAlgorithm languagesClientToServer
    , SshNameList $ supportedAlgorithm languagesServerToClient
    , SshBoolean False -- Not followed by kex packet guess
    , SshUInt32 0
    ]
  where
    supportedAlgorithm f = map nameAsBytestring $ f supportedKexSet

class Named a where
  nameAsBytestring :: a -> ByteString

data KexAlgorithm = KexAlgorithm
  { kexAlgorithmName :: ByteString
  , requresEncryptionCapable :: Bool
  , requresSignatureCapable :: Bool
  } deriving (Eq, Show)

instance Named KexAlgorithm where
  nameAsBytestring = kexAlgorithmName

data HostKeyAlgorithm = HostKeyAlgorithm
  { hostKeyAlgorithmName :: ByteString
  , isEncryptionCapable :: Bool
  , isSignatureCapable :: Bool
  } deriving (Eq, Show)

instance Named HostKeyAlgorithm where
  nameAsBytestring = hostKeyAlgorithmName

data EncryptionAlgorithm = EncryptionAlgorithm
  { encryptionAlgorithmName :: ByteString
  } deriving (Eq, Show)

instance Named EncryptionAlgorithm where
  nameAsBytestring = encryptionAlgorithmName

data MacAlgorithm = MacAlgorithm
  { macAlgorithmName :: ByteString
  } deriving (Eq, Show)

instance Named MacAlgorithm where
  nameAsBytestring = macAlgorithmName

data CompressionAlgorithm = CompressionAlgorithm
  { compressionAlgorithmName :: ByteString
  } deriving (Eq, Show)

instance Named CompressionAlgorithm where
  nameAsBytestring = compressionAlgorithmName

data Language = Language
  { languageName :: ByteString
  } deriving (Eq, Show)

instance Named Language where
  nameAsBytestring = languageName

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
  }

newtype Cookie =
  MkCookie ByteString
  deriving (Show)

algorithmNegotiation :: SshClientServer KexSet -> NegotiatedAlgorithms
algorithmNegotiation ksClientServer =
  NegotiatedAlgorithms
  { negotiatedKexAlgorithm = negotiateKexAlgorithm ksClientServer
  , negotiatedServerHostKeyAlgorithm = negotiateHostKeyAlgorithm ksClientServer
  , negotiatedEncryptionAlgorithmClientToServer = $notImplemented
  , negotiatedEncryptionAlgorithmServerToClient = $notImplemented
  , negotiatedMacAlgorithmClientToServer = $notImplemented
  , negotiatedMacAlgorithmServerToClient = $notImplemented
  , negotiatedCompressionAlgorithmClientToServer = $notImplemented
  , negotiatedCompressionAlgorithmServerToClient = $notImplemented
  , negotiatedLanguageClientToServer = $notImplemented
  , negotiatedLanguageServerToClient = $notImplemented
  }

-- TODO Check whether the algorithm and the host key needs signature-capable and encryption-cappable
negotiateKexAlgorithm :: SshClientServer KexSet -> KexAlgorithm
negotiateKexAlgorithm ksClientServer =
  if head (kexAlgorithms $ clientData ksClientServer) == head (kexAlgorithms $ serverData ksClientServer)
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

supportedKexAlgorithms = [KexAlgorithm "diffie-hellman-group1-sha1" True True, KexAlgorithm "diffie-hellman-group14-sha1" True True]

supportedKeyAlgorithms = [HostKeyAlgorithm "ssh-dss" True True, HostKeyAlgorithm "ssh-rsa" True True]

supportedEncryptionAlgorithms = [EncryptionAlgorithm "3des-cbc"]

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

readKexPacket :: Get (Cookie, KexSet, Bool)
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
  getInt32be
  return (cookie, kexSet, firstKexPacketFollows)

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
knownKexAlgorithms = [buildEntry "diffie-hellman-group1-sha1" True True, buildEntry "diffie-hellman-group14-sha1" True True]
  where
    buildEntry key req1 req2 = (key, KexAlgorithm key req1 req2)

findKexAlgorithm key = fromMaybe (KexAlgorithm key True True) (lookup key knownKexAlgorithms)

knownHostKeyAlgorithms :: [(ByteString, HostKeyAlgorithm)]
knownHostKeyAlgorithms = [buildEntry "ssh-dss" True True, buildEntry "ssh-rsa" True True]
  where
    buildEntry key req1 req2 = (key, HostKeyAlgorithm key req1 req2)

findHostKeyAlgorithm key = fromMaybe (HostKeyAlgorithm key False False) (lookup key knownHostKeyAlgorithms)
