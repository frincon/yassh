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

module Network.Yassh
  -- ( bannerLines
  -- , receiveBanner
  ( protocolExchangeLimitBytes
  , runSshServer
  , SshVersion(..)
  -- , protocolVersionExchangeClient
  -- , protocolVersionExchangeServer
  , sendKexInitPacket
  , supportedKexSet
  , newCookie
  , readPacket
  , readKexPacket
  , algorithmNegotiation
  -- , SshVersion(..)
  , Cookie
  ) where

import Control.Applicative ((<|>))
import Control.Monad (when, void)
import Data.Attoparsec.ByteString (Parser, string, manyTill, anyWord8, takeWhile1, word8)
import Data.Attoparsec.Combinator (lookAhead)
import Data.Maybe (fromMaybe)
import Data.ByteString (ByteString)
import System.IO (hFlush, stdout)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as C8
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Word8 (_hyphen, _space)
import Development.Placeholders
import Network.Socket (PortNumber, Socket, SockAddr)
import Network.Simple.TCP (serve)
import Network.Socket.ByteString (recv, sendAll)
import Paths_yassh (version)
import System.IO.Streams (InputStream, OutputStream)
import qualified System.IO.Streams as Streams
import System.IO.Streams.Attoparsec.ByteString (parseFromStream)
import Data.Binary.Put
import Data.Binary.Get (Get, getWord8, getByteString, getWord32be, getInt32be, runGetIncremental, Decoder(..), runGet)
import Data.Int
import Data.Version (showVersion)
import Network.Yassh.ProtocolVersionExchange (runProtocolVersionExchange)
import Network.Yassh.Internal (SshRole(..), SshVersion(..), SshSettings(..))
import Control.Concurrent.Chan
import Control.Monad.Free

defaultServerSettings :: SshSettings
defaultServerSettings = MkSshSettings
  { sshSettingsOnProtocolVersionExchange = defaultServerOnProtocolVersionExchange
  , sshSettingsOnReceiveBanner = mempty -- no banner from clients
  , sshSettingsProtocolVersionExchangeSizeLimitBytes = defaultProtocolVersionExchangeSizeLimitBytes
  }

defaultServerOnProtocolVersionExchange :: SshVersion -> IO ()
defaultServerOnProtocolVersionExchange = print

defaultProtocolVersionExchangeSizeLimitBytes :: Int64
defaultProtocolVersionExchangeSizeLimitBytes = 64 * 1024

data SshPacket = SshPacket String
data SshSession = SshSession
  { inputStream :: InputStream ByteString
  , outputSrteam :: OutputStream ByteString
  , role :: SshRole
  }


type Shell = ((IO (Maybe ByteString), ByteString -> IO (), ByteString -> IO ()) -> IO ())

runSshServer :: PortNumber -> Shell -> IO ()
runSshServer port shell = serve "*" (show port) (runSshServerConnection shell defaultServerSettings)

-- TODO Shell should be part of the settings
runSshServerConnection :: Shell -> SshSettings -> (Socket, SockAddr) -> IO ()
runSshServerConnection shell settings (connectionSocket, sockAddr) = do
  (is, os) <- Streams.socketToStreams connectionSocket
  limitedInputStream <- Streams.takeBytes (sshSettingsProtocolVersionExchangeSizeLimitBytes settings) is
  sshVersion <- runProtocolVersionExchange (limitedInputStream, os) SshRoleClient settings
  sshSettingsOnProtocolVersionExchange settings sshVersion

protocolTransportLayerGeneric = [1..19]
protocolAlgorithmNegotiation = [20..29]
protocolKeyExchangeSpecific = [30..49]

c_SSH_MSG_KEXINIT = 20

data SshProtocol next =
    RecvPacket [Int] (SshPacket -> next)
  | SendPacket SshPacket next
  | End

instance Functor SshProtocol where
  fmap f (RecvPacket range next) = RecvPacket range (f . next)
  fmap f (SendPacket packet next) = SendPacket packet (f next)
  fmap f End = End

recvPacket :: [Int] -> Free SshProtocol SshPacket
recvPacket range = liftF (RecvPacket range id)

sendPacket :: SshPacket -> Free SshProtocol ()
sendPacket packet = liftF (SendPacket packet ())

end :: Free SshProtocol ()
end = liftF End

-- algorithmNegotiation kexSet = do
--   sendPacket (SshPacket "kexInit")
--   kexInit <- recvPacket [c_SSH_MSG_KEXINIT]
--   --if ()
--   return kexInit

protocolExchangeLimitBytes = 64 * 1024

-- runSshServer :: (InputStream ByteString, OutputStream ByteString) -> IO ()
-- runSshServer = flip runSsh SshRoleServer


newtype Cookie = MkCookie ByteString
  deriving Show

newCookie = MkCookie $ BS.replicate 16 55 -- TODO Random

algorithmNegotiation :: KexSet -> KexSet -> (KexAlgorithm, HostKeyAlgorithm, EncryptionAlgorithm, MacAlgorithm, CompressionAlgorithm)
algorithmNegotiation client server =
  ( negotiateKexAlgorithm client server
  , negotiateHostKeyAlgorithm client server
  , $notImplemented
  , $notImplemented
  , $notImplemented
  )

findFirst :: Eq a => [a] -> [a] -> Maybe a
findFirst [] _= Nothing
findFirst (x:xs) other =
  if elem x other
    then Just x
    else findFirst xs other

-- TODO Check whether the algorithm and the host key needs signature-capable and encryption-cappable
negotiateKexAlgorithm :: KexSet -> KexSet -> KexAlgorithm
negotiateKexAlgorithm = negotiateClientMatch kexAlgorithms "No key exchange algorithm"

-- TODO Check whether the algorithm and the host key needs signature-capable and encryption-cappable
negotiateHostKeyAlgorithm :: KexSet -> KexSet -> HostKeyAlgorithm
negotiateHostKeyAlgorithm = negotiateClientMatch serverHostKeyAlgorithms "No hostkey algorithms"

negotiateClientMatch :: Eq a => (KexSet -> [a]) -> String -> KexSet -> KexSet  -> a
negotiateClientMatch conversion errorMsg client server =
  fromMaybe (error errorMsg) (findFirst (conversion client) (conversion server))


supportedKexAlgorithms =
  [ KexAlgorithm "diffie-hellman-group1-sha1"
  , KexAlgorithm "diffie-hellman-group14-sha1"
  ]
supportedKeyAlgorithms = [HostKeyAlgorithm "ssh-dss", HostKeyAlgorithm "ssh-rsa"]
supportedEncryptionAlgorithms = [EncryptionAlgorithm "3des-cbc"]
supportedMacAlgorithms = [MacAlgorithm "hmac-sha1"]
supportedCompressionAlgorithms = [CompressionAlgorithm "none"]
supportedLanguages = []

class Named a where
  nameAsBytestring :: a -> ByteString

data KexAlgorithm = KexAlgorithm
  { kexAlgorithmName :: ByteString
  }
  deriving (Eq, Show)

instance Named KexAlgorithm where
  nameAsBytestring = kexAlgorithmName

data HostKeyAlgorithm = HostKeyAlgorithm
  { hostKeyAlgorithmName :: ByteString
  }
  deriving (Eq, Show)

instance Named HostKeyAlgorithm where
  nameAsBytestring = hostKeyAlgorithmName

data EncryptionAlgorithm = EncryptionAlgorithm
  { encryptionAlgorithmName :: ByteString
  }
  deriving (Eq, Show)

instance Named EncryptionAlgorithm where
  nameAsBytestring = encryptionAlgorithmName

data MacAlgorithm = MacAlgorithm
  { macAlgorithmName :: ByteString
  }
  deriving (Eq, Show)

instance Named MacAlgorithm where
  nameAsBytestring = macAlgorithmName

data CompressionAlgorithm = CompressionAlgorithm
  { compressionAlgorithmName :: ByteString
  }
  deriving (Eq, Show)

instance Named CompressionAlgorithm where
  nameAsBytestring = compressionAlgorithmName

data Language = Language
  { languageName :: ByteString
  }
  deriving (Eq, Show)

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
  }
  deriving Show

supportedKexSet = KexSet
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

nameList :: Named a => [a] -> Put
nameList list = do
  let listAsByteString = BS.intercalate "," (fmap nameAsBytestring list)
  putWord32be $ fromIntegral $  BS.length listAsByteString
  putByteString listAsByteString

getNameList :: (ByteString -> a) -> Get [a]
getNameList conversion = do
  nameListLength <- fmap fromIntegral getWord32be
  listWithCommans <- getByteString nameListLength
  return $ conversion <$> C8.split ',' listWithCommans

putBoolean :: Bool -> Put
putBoolean False = putWord8 0
putBoolean True = putWord8 1

getBoolean :: Get Bool
getBoolean = do
  value <- getWord8
  if value == 0
    then return False
    else return True

sendKexInitPacket :: KexSet -> Cookie -> OutputStream ByteString -> IO ()
sendKexInitPacket kexSet (MkCookie cookieBytes)=  Streams.write $ Just $ toSshPacket kexPacket
  where
    kexPacket = runPut $ do
      putWord8 20 -- SSH_MSG_KEXINIT TODO Make constant
      putByteString cookieBytes
      nameList $ kexAlgorithms kexSet
      nameList $ serverHostKeyAlgorithms kexSet
      nameList $ encryptionAlgorithmsClientToServer kexSet
      nameList $ encryptionAlgorithmsServerToClient kexSet
      nameList $ macAlgorithmsClientToServer kexSet
      nameList $ macAlgorithmsServerToClient kexSet
      nameList $ compressionAlgorithmsClientToServer kexSet
      nameList $ compressionAlgorithmsServerToClient kexSet
      nameList $ languagesClientToServer kexSet
      nameList $ languagesServerToClient kexSet
      putBoolean False
      putInt32be 0

readPacket :: InputStream ByteString -> Get a -> IO a
readPacket is reader = go decoder
  where
    decoder = runGetIncremental $ do
      payload <- readSshPacketPayload
      return $ runGet reader $ LBS.fromStrict payload
    go (Partial continue) = do
      maybeBuffer <- Streams.read is
      go $ continue maybeBuffer
    go (Done leftover _ result) = do
      Streams.unRead leftover is
      return result
    go (Fail leftover _ msg) = do
      Streams.unRead leftover is
      fail msg

readPacketPayload :: InputStream ByteString -> IO ByteString
readPacketPayload is = readFromInputStream is readSshPacketPayload

readFromInputStream :: InputStream ByteString -> Get a -> IO a
readFromInputStream is reader = go decoder
  where
    decoder = runGetIncremental reader
    go (Partial continue) = do
      maybeBuffer <- Streams.read is
      go $ continue maybeBuffer
    go (Done leftover _ result) = do
      Streams.unRead leftover is
      return result
    go (Fail leftover _ msg) = do
      Streams.unRead leftover is
      fail msg

newtype Payload = Payload ByteString

readSshPacketPayload :: Get ByteString
readSshPacketPayload = do
  packetLength <- fmap fromIntegral getWord32be
  paddingLength <- fmap fromIntegral getWord8
  payload <- getByteString $ packetLength - paddingLength - 1 - 1
  getByteString paddingLength
  return payload

readKexPacket :: Get (Cookie, KexSet, Bool)
readKexPacket = do
  messageNumber <- getWord8
  when (messageNumber /= 20) $ fail "The packet was not a SSH_MSG_KEXINIT packet" -- TODO
  cookie <- fmap MkCookie (getByteString 16)
  kexSet <- KexSet
    <$> getNameList KexAlgorithm
    <*> getNameList HostKeyAlgorithm
    <*> getNameList EncryptionAlgorithm
    <*> getNameList EncryptionAlgorithm
    <*> getNameList MacAlgorithm
    <*> getNameList MacAlgorithm
    <*> getNameList CompressionAlgorithm
    <*> getNameList CompressionAlgorithm
    <*> getNameList Language
    <*> getNameList Language
  firstKexPacketFollows <- getBoolean
  getInt32be
  return (cookie, kexSet, firstKexPacketFollows)

toSshPacket :: LBS.ByteString -> BS.ByteString
toSshPacket payload = BS.concat $ LBS.toChunks $ LBS.concat -- TODO Not very efficient
  [ runPut $ putWord32be $ fromIntegral paketLength
  , runPut $ putWord8 $ fromIntegral paddingLength
  , payload
  , LBS.replicate (fromIntegral paddingLength) 0 -- TODO Use Random
  ]
  where
    payloadLength :: Int64
    payloadLength = LBS.length payload
    paketLengthFieldLength :: Int64
    paketLengthFieldLength = 4 :: Int64
    paddingLengthFieldLength :: Int64
    paddingLengthFieldLength = 1 :: Int64
    paddingLength :: Int64
    paddingLength = 8 - ((payloadLength + paketLengthFieldLength + paddingLengthFieldLength) `mod` 8)
    paketLength :: Int64
    paketLength = paddingLengthFieldLength + payloadLength + paddingLength
