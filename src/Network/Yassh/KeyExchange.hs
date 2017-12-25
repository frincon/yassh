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
import Data.ByteArray (ByteArray, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Either (either)
import Data.Maybe (fromMaybe, fromJust)
import Data.Proxy (Proxy(Proxy))
import Data.Word8 (Word8)
import Development.Placeholders
import Network.Yassh.Internal
import Network.Yassh.Internal.KeyExchange
import Network.Yassh.KeyExchange.DiffieHellman --TODO This should not be here

{-
data SshPacketKexInit = SshPacketKexInit
  { kexInitCookie :: Cookie
  , kexInitKexAlgorithms :: [ByteString]
  , kexInitHostKeyAlgorithms :: [ByteString]
  , kexInitEncryptionAlgorithmsClientToServer :: [ByteString]
  , kexInitEncryptionAlgorithmsServerToClient :: [ByteString]
  , kexInitKexAlgorithms :: [ByteString]
  , kexInitKexAlgorithms :: [ByteString]
  , kexInitKexAlgorithms :: [ByteString]
  , kexInitKexAlgorithms :: [ByteString]
  , kexInitFirstKexPacketFollow :: Bool
  } deriving (Show)

instance ToSshPacket SshPacketKexInit where
  toSshPacket SshPacketKexInit { kexInitCookie = (MkCookie cookieBytes)
                               , kexInitKexSet = kexSet
                               , kexInitFirstKexPacketFollow = firstKexPacketFollows
                               } =
    where
      extractNameList f = f kexSet

instance FromSshRawPacket SshPacketKexInit where
  fromSshRawPacket (SshRawPacket _ payload) = runGet readKexPacket $ LBS.fromStrict payload
  expectedMsgId _ = c_SSH_MSG_KEXINIT
-}

-- TODO The first kexAlgorithm should be supported by the host key algorithm
sshPacketKexInit :: Cookie -> KexSet -> SshPacket
sshPacketKexInit (MkCookie cookieBytes) kexSet =
  SshPacket
      c_SSH_MSG_KEXINIT
      [ SshByteArray 16 cookieBytes -- TODO Ensure 16 bytes
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
      , SshBoolean False
      , SshUInt32 0 -- Future use
      ]

data SshDirectional t = SshDirectional
  { clientToServer :: t
  , serverToClient :: t
  }

bothDirections :: t -> SshDirectional t
bothDirections param = SshDirectional param param

runKeyExchange ::
     SshRole -> SshClientServer SshVersion -> [KexAlgorithm] -> ([Word8] -> IO SshRawPacket) -> (SshPacket -> IO ()) -> IO ()
runKeyExchange role versions kexAlgs recv send
    -- TODO Remove this from here
 = do
  (publicHostKey, privateHostKey) <- generate 256 65537
  print publicHostKey
    -- End
  putStrLn "Running key exchange"
  let cookie = newCookie
  let kexInitRawPacketSent = toSshRawPacket $ sshPacketKexInit $ cookie (supportedKexSet kexAlgs)
  send $ sshPacketKexInit $ cookie (supportedKexSet kexAlgs) -- TODO Send should return payload and encripted payload?
  putStrLn "SSH_MSG_KEXINIT Sent"
  kexInitRawPacketReceived <- recv [c_SSH_MSG_KEXINIT]
  let kexInitReceived = fromSshRawPacket kexInitRawPacketReceived
  putStrLn "SSH_MSG_KEXINIT Received"
  when
    (kexInitFirstKexPacketFollow kexInitReceived && guessIsWrong (kexInitKexSet kexInitReceived) (supportedKexSet kexAlgs))
    (void $ recv [30 .. 49]) -- Discard the next packet
  putStrLn $ "Received Kex Algorithm" ++ (show $ kexAlgorithms $ kexInitKexSet kexInitReceived)
  putStrLn $ "Sent Kex Algorithm" ++ (show $ kexAlgorithms $ supportedKexSet kexAlgs)
  let result = algorithmNegotiation $ fromRole role (supportedKexSet kexAlgs) (kexInitKexSet kexInitReceived)
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
              sshEncode [SshString "ssh-rsa", SshString $ either (error . show) id $ sign Nothing (Just SHA1) privateHostKey toSign]
        }
  keyAndExchange <- (runKex $ negotiatedKexAlgorithm result) role kexContext recv send
  recv [0 .. 100]
  return ()
  where
    guessIsWrong :: KexSet -> KexSet -> Bool
    guessIsWrong received sent =
      (head (kexAlgorithms received) /= head (kexAlgorithms sent)) ||
      (head (serverHostKeyAlgorithms received) /= head (serverHostKeyAlgorithms sent))
    encodeRsaPubKey (PublicKey _ n e) = sshEncode [SshString "ssh-rsa", SshMPint e, SshMPint n]

data KexSet = KexSet
  { kexAlgorithms :: [KexAlgorithm]
  , serverHostKeyAlgorithms :: [HostKeyAlgorithm]
  , encryptionAlgorithms :: SshDirectional [EncryptionAlgorithm]
  , macAlgorithms :: SshDirectional [MacAlgorithm]
  , compressionAlgorithms :: SshDirectional [CompressionAlgorithm]
  , languages :: SshDirectional [Language]
  } deriving (Show)

data NegotiatedProtocol = NegotiatedProtocol
  { negotiatedEncryptionAlgorithm :: EncryptionAlgorithm
  , negotiatedMacAlgorithm :: MacAlgorithm
  , negotiatedCompressionAlgorithm :: CompressionAlgorithm
  , negotiatedLanguage :: Maybe Language
  }

data NegotiatedAlgorithms = NegotiatedAlgorithms
  { negotiatedKexAlgorithm :: KexAlgorithm
  , negotiatedServerHostKeyAlgorithm :: HostKeyAlgorithm
  , negotiatedProtocols :: SshDirectional NegotiatedProtocol
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
negotiateKexAlgorithm :: ([KexAlgorithm], [HostKeyAlgorithm]) -> SshClientServer [ByteString] -> SshClientServer [ByteString] -> KexAlgorithm
negotiateKexAlgorithm (supportedKex, supportedHost) kexClientServer hostClientServer =
  if head (clientData kexClientServer) == head (serverData kexClientServer) -- The guess
    then fromJust $ find (\alg -> nameAsBytestring alg == head (clientData kexClientServer)) supportedKex
    else findKexAlgorithm
  where
    findKexAlgorithm 

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

supportedKeyAlgorithms = [HostKeyAlgorithm "ssh-dss" True True, HostKeyAlgorithm "ssh-rsa" True True]

supportedEncryptionAlgorithms = [EncryptionAlgorithm "aes128-cbc", EncryptionAlgorithm "3des-cbc"]

supportedMacAlgorithms = [MacAlgorithm "hmac-sha1"]

supportedCompressionAlgorithms = [CompressionAlgorithm "none"]

supportedLanguages = []

supportedKexSet kexAlgs =
  KexSet
  { kexAlgorithms = kexAlgs
  , serverHostKeyAlgorithms = supportedKeyAlgorithms
  , encryptionAlgorithms = bothDirections supportedEncryptionAlgorithms
  , macAlgorithms = bothDirections supportedMacAlgorithms
  , compressionAlgorithms = bothDirections supportedCompressionAlgorithms
  , languages = bothDirections supportedLanguages
  }


readKexPacket :: Get SshPacketKexInit
readKexPacket = do
  cookie <- fmap MkCookie (getByteString 16)
  kexSet <-
    KexSet <$> getNameList id <*> getNameList findHostKeyAlgorithm <*> getNameList EncryptionAlgorithm <*>
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

knownHostKeyAlgorithms :: [(ByteString, HostKeyAlgorithm)]
knownHostKeyAlgorithms = [buildEntry "ssh-dss" True True, buildEntry "ssh-rsa" True True]
  where
    buildEntry key req1 req2 = (key, HostKeyAlgorithm key req1 req2)

findHostKeyAlgorithm key = fromMaybe (HostKeyAlgorithm key False False) (lookup key knownHostKeyAlgorithms)
