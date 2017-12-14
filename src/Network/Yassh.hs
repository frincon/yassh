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
  ( runSshServer
  , runSshClient
  , defaultServerSettings
  , defaultClientSettings
  , SshVersion(..)
  -- , protocolVersionExchangeClient
  -- , protocolVersionExchangeServer
  , SshAction
  , SshContext
  ) where

import Control.Applicative ((<|>))
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (async, wait)
import Control.Concurrent.Chan
import Control.Exception (SomeException, catch)
import Control.Monad (void, when)
import Control.Monad.Catch (MonadMask)
import Control.Monad.Free
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT, ask, asks, local, runReaderT)
import Data.Attoparsec.ByteString
       (Parser, anyWord8, manyTill, string, takeWhile1, word8)
import Data.Attoparsec.Combinator (lookAhead)
import Data.Binary.Get
       (Decoder(..), Get, getByteString, getInt32be,
        getRemainingLazyByteString, getWord32be, getWord8, runGet,
        runGetIncremental)
import Data.Binary.Put
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Int
import Data.Maybe (fromJust, fromMaybe, isNothing)
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
import Network.Yassh.Internal.ProtocolVersionExchange
       (runProtocolVersionExchange)
import Network.Yassh.KeyExchange (runKeyExchange)
import Paths_yassh (version)
import System.IO (hFlush, stdout)
import System.IO.Streams (InputStream, OutputStream)
import qualified System.IO.Streams as Streams
import System.IO.Streams.Attoparsec.ByteString (parseFromStream)

import Data.Bits

libraryName = "yassh"

defaultServerSettings :: SshSettings
defaultServerSettings =
  MkSshSettings
  { sshSettingsOnProtocolVersionExchange = defaultOnProtocolVersionExchange
  , sshSettingsOnReceiveBanner = mempty -- no banner from clients
  , sshSettingsProtocolVersionExchangeSizeLimitBytes = defaultProtocolVersionExchangeSizeLimitBytes
  , sshSettingsIgnoreInterval = defaultIgnoreInterval
  , sshSettingsVersion = defaultVersion
  }

defaultClientSettings :: SshSettings
defaultClientSettings =
  MkSshSettings
  { sshSettingsOnProtocolVersionExchange = defaultOnProtocolVersionExchange
  , sshSettingsOnReceiveBanner = BS.putStr -- print banner to stdout
  , sshSettingsProtocolVersionExchangeSizeLimitBytes = maxBound
  , sshSettingsIgnoreInterval = defaultIgnoreInterval
  , sshSettingsVersion = defaultVersion
  }

defaultVersion :: SshVersion
defaultVersion = SshVersion "2.0" (BS.concat [libraryName, "-", C8.pack $ showVersion version]) Nothing

defaultOnProtocolVersionExchange :: SshVersion -> IO ()
defaultOnProtocolVersionExchange = print

defaultProtocolVersionExchangeSizeLimitBytes :: Int64
defaultProtocolVersionExchangeSizeLimitBytes = 64 * 1024

defaultIgnoreInterval :: TimeSpan
defaultIgnoreInterval = minutes 1

type Shell = ((IO (Maybe ByteString), ByteString -> IO (), ByteString -> IO ()) -> IO ())

-- TODO Check if we can get rid of MonadMask
runSshClient :: (MonadIO m, MonadMask m) => String -> SshAction m r -> m r
runSshClient hostName program = connect hostName "22" (runSshClientConnection program defaultClientSettings)

runSshServer :: PortNumber -> Shell -> IO ()
runSshServer port shell = serve "*" (show port) (runSecure . runSshServerConnection shell defaultServerSettings)

runSecure :: IO () -> IO ()
runSecure program = catch program (\e -> print (e :: SomeException))

-- TODO Shell should be part of the settings
runSshServerConnection :: MonadIO m => Shell -> SshSettings -> (Socket, SockAddr) -> m ()
runSshServerConnection shell settings (connectionSocket, sockAddr) = do
  context <- initializeConnection settings SshRoleServer connectionSocket
  -- TODO Run the shell
  return ()

runSshClientConnection :: MonadIO m => SshAction m r -> SshSettings -> (Socket, SockAddr) -> m r
runSshClientConnection program settings (connectionSocket, sockAddr) = do
  context <- initializeConnection settings SshRoleClient connectionSocket
  runReaderT program context

initializeConnection :: MonadIO m => SshSettings -> SshRole -> Socket -> m SshContext
initializeConnection settings role socket = do
  streams <- liftIO $ Streams.socketToStreams socket
  version <- protocolExchange streams settings role
  packetStreams <- liftIO $ createPacketStreams streams
  let context = MkSshContext role streams settings version packetStreams
  runReaderT runFirstKeyExchange context

protocolExchange :: MonadIO m => (InputStream ByteString, OutputStream ByteString) -> SshSettings -> SshRole -> m SshVersion
protocolExchange (is, os) settings role = do
  limitedInputStream <- liftIO $ Streams.takeBytes (sshSettingsProtocolVersionExchangeSizeLimitBytes settings) is
  sshVersion <- liftIO $ runProtocolVersionExchange (limitedInputStream, os) role settings
  liftIO $ sshSettingsOnProtocolVersionExchange settings sshVersion
  return sshVersion

-- until here is ok TODO Refactor from here
runFirstKeyExchange :: MonadIO m => ReaderT SshContext m SshContext
runFirstKeyExchange = do
  (is, os) <- asks sshContextPacketStreams
  role <- asks sshContextRole
  settings <- asks sshContextSettings
  peerVersion <- asks sshContextPeerVersion
  result <-
    liftIO $
    runKeyExchange
      role
      (fromRole role (sshSettingsVersion settings) (peerVersion))
      (receivePacket is)
      (\p -> (putStrLn "Sending packet" >> (Streams.writeTo os $ Just p)))
  ask -- TODO Make another context with the keys
  where
    receivePacket :: InputStream SshRawPacket -> [Word8] -> IO SshRawPacket
    receivePacket is accepted = do
      maybeSshRawPacket <- Streams.read is
      case maybeSshRawPacket of
        Nothing -> fail "Connection close while doing the first key exchange"
        Just sshRawPacket@(SshRawPacket msg payload) -> do
          putStrLn $ "Msg received: " ++ (show msg)
          if msg `elem` accepted
            then return sshRawPacket
            else do
              processOtherPacket sshRawPacket
              receivePacket is accepted
    processOtherPacket paket = $notImplemented

sendPacket :: MonadIO m => SshPacket -> ReaderT SshContext m ()
sendPacket packet = do
  (_, os) <- asks sshContextPacketStreams
  liftIO $ Streams.write (Just packet) os
  return ()

receivePacket :: MonadIO m => [Word8] -> ReaderT SshContext m SshRawPacket
receivePacket = $notImplemented

sshMsgIgnoreHandler :: MonadIO m => ReaderT SshContext m ()
sshMsgIgnoreHandler = do
  liftIO $ putStrLn "Prepared to receive an ignore packet"
  packet <- receivePacket [c_SSH_MSG_IGNORE]
  liftIO $ putStrLn "Ignore packet received"
  sshMsgIgnoreHandler

sshMsgIgnoreSender :: MonadIO m => ReaderT SshContext m ()
sshMsgIgnoreSender = do
  interval <- asks (sshSettingsIgnoreInterval . sshContextSettings)
  runSshMsgIngnoreSender interval
  where
    runSshMsgIngnoreSender :: MonadIO m => TimeSpan -> ReaderT SshContext m ()
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
    createPacketOutputStream os =
      Streams.makeOutputStream $ -- TODO use fmap
       \case
        Nothing -> Streams.write Nothing os
        Just packet -> Streams.write (Just $ sshPacketToByteString packet) os

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
  payload <- getByteString $ packetLength - paddingLength - 1
  getByteString paddingLength
  return payload

readRawPacket :: Get SshRawPacket
readRawPacket = SshRawPacket <$> getWord8 <*> fmap (BS.concat . LBS.toChunks) getRemainingLazyByteString

sshPacketToByteString :: SshPacket -> BS.ByteString
sshPacketToByteString packet = sshPacketToByteString' $ runPut (putPacket $ toSshRawPacket packet)
  where
    putPacket :: SshRawPacket -> Put
    putPacket (SshRawPacket msgId payload) = do
      putWord8 msgId
      putByteString payload

sshPacketToByteString' :: LBS.ByteString -> BS.ByteString
sshPacketToByteString' payload =
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
-- runSshServer = flip runSsh SshRoleServer
  {-
nameList :: Named a => [a] -> Put
nameList list = do
  let listAsByteString = BS.intercalate "," (fmap nameAsBytestring list)
  putWord32be $ fromIntegral $ BS.length listAsByteString
  putByteString listAsByteString


putBoolean :: Bool -> Put
putBoolean False = putWord8 0
putBoolean True = putWord8 1


sendKexInitPacket :: KexSet -> Cookie -> OutputStream ByteString -> IO ()
sendKexInitPacket kexSet (MkCookie cookieBytes) = Streams.write $ Just $ sshPacketToByteString kexPacket
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


-}
