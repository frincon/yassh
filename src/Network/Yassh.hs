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
{-# LANGUAGE LambdaCase #-}

module Network.Yassh
  -- ( bannerLines
  -- , receiveBanner
  ( protocolExchangeLimitBytes
  , runSshServer
  , runSshClient
  , defaultServerSettings
  , defaultClientSettings
  , SshVersion(..)
  -- , protocolVersionExchangeClient
  -- , protocolVersionExchangeServer
  , SshAction
  , SshContext
  , SshClientContext
  ) where

import Control.Applicative ((<|>))
import Control.Concurrent (threadDelay)
import Control.Concurrent.Chan
import Control.Monad (void, when)
import Control.Monad.Catch (MonadMask)
import Control.Monad.Free
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT, ask, asks, local, runReaderT)
import Data.Attoparsec.ByteString
       (Parser, anyWord8, manyTill, string, takeWhile1, word8)
import Data.Attoparsec.Combinator (lookAhead)
import Data.Binary.Get
       (Decoder(..), Get, getByteString, getInt32be, getWord32be,
        getWord8, runGet, runGetIncremental, getRemainingLazyByteString)
import Data.Binary.Put
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Int
import Data.Maybe (fromMaybe, fromJust)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time.TimeSpan (TimeSpan, minutes, toMicroseconds)
import Data.Version (showVersion)
import Data.Word8 (Word8, _hyphen, _space)
import Development.Placeholders
import Network.Simple.TCP (connect, serve)
import Network.Socket (PortNumber, SockAddr, Socket)
import Network.Socket.ByteString (recv, sendAll)
import Network.Yassh.Internal
import Network.Yassh.ProtocolVersionExchange
       (runProtocolVersionExchange)
import Paths_yassh (version)
import System.IO (hFlush, stdout)
import System.IO.Streams (InputStream, OutputStream)
import qualified System.IO.Streams as Streams
import System.IO.Streams.Attoparsec.ByteString (parseFromStream)

defaultServerSettings :: SshSettings
defaultServerSettings =
  MkSshSettings
  { sshSettingsOnProtocolVersionExchange = defaultOnProtocolVersionExchange
  , sshSettingsOnReceiveBanner = mempty -- no banner from clients
  , sshSettingsProtocolVersionExchangeSizeLimitBytes = defaultProtocolVersionExchangeSizeLimitBytes
  , sshSettingsIgnoreInterval = defaultIgnoreInterval
  }

defaultClientSettings :: SshSettings
defaultClientSettings =
  MkSshSettings
  { sshSettingsOnProtocolVersionExchange = defaultOnProtocolVersionExchange
  , sshSettingsOnReceiveBanner = BS.putStr -- print banner to stdout
  , sshSettingsProtocolVersionExchangeSizeLimitBytes = maxBound
  , sshSettingsIgnoreInterval = defaultIgnoreInterval
  }

defaultOnProtocolVersionExchange :: SshVersion -> IO ()
defaultOnProtocolVersionExchange = print

defaultProtocolVersionExchangeSizeLimitBytes :: Int64
defaultProtocolVersionExchangeSizeLimitBytes = 64 * 1024

defaultIgnoreInterval :: TimeSpan
defaultIgnoreInterval = minutes 1

type Shell = ((IO (Maybe ByteString), ByteString -> IO (), ByteString -> IO ()) -> IO ())

-- TODO Check if we can get rid of MonadMask
runSshClient :: (MonadIO m, MonadMask m) => String -> SshAction SshClientContext m r -> m r
runSshClient hostName program = connect hostName "22" (runSshClientConnection program defaultClientSettings)

runSshServer :: PortNumber -> Shell -> IO ()
runSshServer port shell = serve "*" (show port) (runSshServerConnection shell defaultServerSettings)

-- TODO Shell should be part of the settings
runSshServerConnection :: MonadIO m => Shell -> SshSettings -> (Socket, SockAddr) -> m ()
runSshServerConnection shell settings (connectionSocket, sockAddr) = do
  context <- sshContext connectionSocket MkSshServerContext SshRoleServer settings
  runReaderT initializeConnection context
  return ()

runSshClientConnection :: MonadIO m => SshAction SshClientContext m r -> SshSettings -> (Socket, SockAddr) -> m r
runSshClientConnection program settings (connectionSocket, sockAddr) = do
  context <- sshContext connectionSocket MkSshClientContext SshRoleClient settings
  runReaderT (protocolExchange >> program) context

initializeConnection :: MonadIO m => ReaderT (SshContext t) m ()
initializeConnection = do
  version <- protocolExchange
  local (\c -> c {sshContextPeerVersion = Just version}) $ do
    streams <- asks sshContextStreams
    packetStreams <- liftIO $ createPacketStreams streams
    local (\c -> c {sshContextPacketStreams = Just packetStreams }) sshMsgIgnoreHandler
  return ()

protocolExchange :: MonadIO m => ReaderT (SshContext t) m SshVersion
protocolExchange = do
  (is, os) <- asks sshContextStreams
  settings <- asks sshContextSettings
  role <- asks sshContextRole
  limitedInputStream <- liftIO $ Streams.takeBytes (sshSettingsProtocolVersionExchangeSizeLimitBytes settings) is
  sshVersion <- liftIO $ runProtocolVersionExchange (limitedInputStream, os) role settings
  liftIO $ sshSettingsOnProtocolVersionExchange settings sshVersion
  return sshVersion

sshContext :: MonadIO m => Socket -> t -> SshRole -> SshSettings -> m (SshContext t)
sshContext socket cons role settings = do
  streams <- liftIO $ Streams.socketToStreams socket
  return
    MkSshContext
    { sshContextSpecificContext = cons
    , sshContextRole = role
    , sshContextStreams = streams
    , sshContextSettings = settings
    , sshContextPeerVersion = Nothing
    }

-- until here is ok TODO Refactor from here
sendPacket :: SshPacket -> ReaderT (SshContext t) m ()
sendPacket = $notImplemented

receivePacket :: MonadIO m => [Word8] -> (SshRawPacket -> ReaderT (SshContext t) m r) -> ReaderT (SshContext t) m r
receivePacket expected action = do
  (is, _) <- asks (fromJust . sshContextPacketStreams)
  maybePacket <- liftIO $ Streams.read is
  case maybePacket of
    Nothing -> fail "No more data" -- TODO Is this correct?
    Just packet@(SshRawPacket msgId _) ->
      if msgId `elem` expected
        then action packet
        else do
          liftIO $ Streams.unRead packet is
          receivePacket expected action

c_SSH_MSG_KEXINIT = 20 :: Word8

c_SSH_MSG_IGNORE = 2 :: Word8

sshMsgIgnoreHandler :: MonadIO m => ReaderT (SshContext t) m ()
sshMsgIgnoreHandler = do
  liftIO $ putStrLn "Receiving ignore packets"
  receivePacket [c_SSH_MSG_IGNORE] $ \packet -> do
    liftIO $ putStrLn "Ignore packet received"
    sshMsgIgnoreHandler
  liftIO $ putStrLn "Finish handler"

sshMsgIgnoreSender :: MonadIO m => ReaderT (SshContext t) m ()
sshMsgIgnoreSender = do
  interval <- asks (sshSettingsIgnoreInterval . sshContextSettings)
  runSshMsgIngnoreSender interval
  where
    runSshMsgIngnoreSender :: MonadIO m => TimeSpan -> ReaderT (SshContext t) m ()
    runSshMsgIngnoreSender interval = do
      liftIO $ threadDelay (round $ toMicroseconds interval) -- TODO The interval should be random
      sendPacket $ SshPacket c_SSH_MSG_IGNORE [SshString "some data to be random"] -- TODO This should be random
      runSshMsgIngnoreSender interval

createPacketStreams :: (InputStream ByteString, OutputStream ByteString) -> IO (InputStream SshRawPacket, OutputStream SshPacket)
createPacketStreams (is, os) = do
    newIs <- createPacketInputStream is
    newOs <- createPacketOutputStream os
    return (newIs, newOs)
  where
    createPacketInputStream is = Streams.makeInputStream $ readPacket is readRawPacket
    createPacketOutputStream :: OutputStream ByteString -> IO (OutputStream SshPacket)
    createPacketOutputStream os = Streams.makeOutputStream $ \case -- TODO use fmap
      Nothing -> Streams.write Nothing os
      Just packet -> Streams.write (Just $ toSshPacket packet) os

readPacket :: InputStream ByteString -> Get a -> IO (Maybe a)
readPacket is reader = go decoder
  where
    decoder =
      runGetIncremental $ do
        payload <- readSshPacketPayload
        return $ runGet reader $ LBS.fromStrict payload
    go (Partial continue) = do
      maybeBuffer <- Streams.read is
      go $ continue maybeBuffer
    go (Done leftover _ result) = do
      Streams.unRead leftover is
      return $ Just result
    go (Fail leftover _ msg) = do
      Streams.unRead leftover is
      return Nothing

readSshPacketPayload :: Get ByteString
readSshPacketPayload = do
  packetLength <- fmap fromIntegral getWord32be
  paddingLength <- fmap fromIntegral getWord8
  payload <- getByteString $ packetLength - paddingLength - 1 - 1
  getByteString paddingLength
  return payload

readRawPacket :: Get SshRawPacket
readRawPacket = SshRawPacket
    <$> getWord8
    <*> fmap (BS.concat . LBS.toChunks) getRemainingLazyByteString


toSshPacket :: SshPacket -> BS.ByteString
toSshPacket packet = toSshPacket' $ runPut (putPacket packet)
  where
    putPacket :: SshPacket -> Put
    putPacket (SshPacket msgId otherData) = do
      putWord8 msgId
      mapM_ dataToPut otherData
    dataToPut :: SshData -> Put
    dataToPut (SshString payload) = do
      putWord32be $ fromIntegral $ BS.length payload
      putByteString payload
    dataToPut (SshBoolean True) = putWord8 1
    dataToPut (SshBoolean False) = putWord8 0

toSshPacket' :: LBS.ByteString -> BS.ByteString
toSshPacket' payload =
  BS.concat $
  LBS.toChunks $
  LBS.concat -- TODO Not very efficient
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

-- Until here is not checked
protocolTransportLayerGeneric = [1 .. 19]

protocolAlgorithmNegotiation = [20 .. 29]

protocolKeyExchangeSpecific = [30 .. 49]


{-
data SshProtocol next
  = RecvPacket [Int]
               (SshPacket -> next)
  | SendPacket SshPacket
               next
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
-}
-- algorithmNegotiation kexSet = do
--   sendPacket (SshPacket "kexInit")
--   kexInit <- recvPacket [c_SSH_MSG_KEXINIT]
--   --if ()
--   return kexInit
protocolExchangeLimitBytes = 64 * 1024

-- runSshServer :: (InputStream ByteString, OutputStream ByteString) -> IO ()
-- runSshServer = flip runSsh SshRoleServer
newtype Cookie =
  MkCookie ByteString
  deriving (Show)

newCookie = MkCookie $ BS.replicate 16 55 -- TODO Random

algorithmNegotiation ::
     KexSet -> KexSet -> (KexAlgorithm, HostKeyAlgorithm, EncryptionAlgorithm, MacAlgorithm, CompressionAlgorithm)
algorithmNegotiation client server =
  (negotiateKexAlgorithm client server, negotiateHostKeyAlgorithm client server, $notImplemented, $notImplemented, $notImplemented)

findFirst :: Eq a => [a] -> [a] -> Maybe a
findFirst [] _ = Nothing
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

negotiateClientMatch :: Eq a => (KexSet -> [a]) -> String -> KexSet -> KexSet -> a
negotiateClientMatch conversion errorMsg client server =
  fromMaybe (error errorMsg) (findFirst (conversion client) (conversion server))

supportedKexAlgorithms = [KexAlgorithm "diffie-hellman-group1-sha1", KexAlgorithm "diffie-hellman-group14-sha1"]

supportedKeyAlgorithms = [HostKeyAlgorithm "ssh-dss", HostKeyAlgorithm "ssh-rsa"]

supportedEncryptionAlgorithms = [EncryptionAlgorithm "3des-cbc"]

supportedMacAlgorithms = [MacAlgorithm "hmac-sha1"]

supportedCompressionAlgorithms = [CompressionAlgorithm "none"]

supportedLanguages = []

class Named a where
  nameAsBytestring :: a -> ByteString

data KexAlgorithm = KexAlgorithm
  { kexAlgorithmName :: ByteString
  } deriving (Eq, Show)

instance Named KexAlgorithm where
  nameAsBytestring = kexAlgorithmName

data HostKeyAlgorithm = HostKeyAlgorithm
  { hostKeyAlgorithmName :: ByteString
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

{-
nameList :: Named a => [a] -> Put
nameList list = do
  let listAsByteString = BS.intercalate "," (fmap nameAsBytestring list)
  putWord32be $ fromIntegral $ BS.length listAsByteString
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
sendKexInitPacket kexSet (MkCookie cookieBytes) = Streams.write $ Just $ toSshPacket kexPacket
  where
    kexPacket =
      runPut $ do
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

newtype Payload =
  Payload ByteString


readKexPacket :: Get (Cookie, KexSet, Bool)
readKexPacket = do
  messageNumber <- getWord8
  when (messageNumber /= 20) $ fail "The packet was not a SSH_MSG_KEXINIT packet" -- TODO
  cookie <- fmap MkCookie (getByteString 16)
  kexSet <-
    KexSet <$> getNameList KexAlgorithm <*> getNameList HostKeyAlgorithm <*> getNameList EncryptionAlgorithm <*>
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
-}
