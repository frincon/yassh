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

module Network.Yassh.Internal.KeyExchange
  ( runKeyExchangeServer
  ) where

import Control.Monad (void, when)
import Crypto.Hash
import Data.Function (on)

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.PubKey.DH

-- import Crypto.PubKey.RSA
-- import Crypto.PubKey.RSA.PKCS15
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.ByteArray (convert)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy as LBS
import Data.Either (either)
import Data.List (find)
import Data.Maybe (catMaybes, fromMaybe, isJust, maybe)
import Data.Proxy (Proxy(Proxy))
import Data.Proxy (Proxy(Proxy))
import Data.Word (Word8)
import Data.Word8 (Word8)
import Development.Placeholders
import Development.Placeholders
import qualified Network.Yassh.HostKey as HostKey
import Network.Yassh.Internal
import qualified Network.Yassh.KeyExchange as KeyExchange

newtype Cookie =
  MkCookie ByteString
  deriving (Show)

data NegotiationSet = NegotiationSet
  { kexAlgs :: [ByteString]
  , serverHostKeyAlgs :: [ByteString]
  , encryptionAlgs :: BiDirectional [ByteString]
  , macAlgs :: BiDirectional [ByteString]
  , compressionAlgs :: BiDirectional [ByteString]
  , languages :: BiDirectional [ByteString]
  }

data BiDirectional a = BiDirectional
  { clientToServer :: a
  , serverToClient :: a
  }

newCookie :: Cookie
newCookie = MkCookie $ BS.replicate 16 55 -- TODO make random

-- TODO Support different algorithms server to client thatn client to server
-- TODO Support following first paket?
mkSshPacketKexInit :: Cookie -> NegotiationSet -> SshPacket
mkSshPacketKexInit (MkCookie cookieBytes) negotiationSet =
  SshPacket
    c_SSH_MSG_KEXINIT
    [ SshByteArray 16 cookieBytes
    , SshNameList $ kexAlgs negotiationSet
    , SshNameList $ serverHostKeyAlgs negotiationSet
    , SshNameList $ clientToServer $ encryptionAlgs negotiationSet
    , SshNameList $ serverToClient $ encryptionAlgs negotiationSet
    , SshNameList $ clientToServer $ macAlgs negotiationSet
    , SshNameList $ serverToClient $ macAlgs negotiationSet
    , SshNameList $ clientToServer $ compressionAlgs negotiationSet
    , SshNameList $ serverToClient $ compressionAlgs negotiationSet
    , SshNameList $ clientToServer $ languages negotiationSet
    , SshNameList $ serverToClient $ languages negotiationSet
    , SshBoolean False
    , SshUInt32 0 -- Future use
    ]

tempEncryptionAlgs = ["aes128-ctr", "3des-cbc"] :: [ByteString]

tempMacAlgs = ["hmac-sha1"]

tempCompressionAlgs = ["none"]

tempLanguages = []

runKeyExchangeServer ::
     [HostKey.ServerHandle]
  -> [KeyExchange.ServerHandle]
  -> SshClientServer SshVersion
  -> ([Word8] -> IO SshRawPacket)
  -> (SshPacket -> IO ())
  -> IO ()
runKeyExchangeServer hostKeyHandlers keyExchangeHandles versions recv send = do
  putStrLn "Running key exchange"
  (hostKeyHandle, keyExchangeHandle, msgInit) <- doAlgorithmNegotiation hostKeyHandlers keyExchangeHandles recv send
  let kexContext =
        KeyExchange.KexContext
        { KeyExchange.kexContextIdentificationString = fmap toIdentificationString versions
        , KeyExchange.kexContextMsgInit = msgInit
        , KeyExchange.kexContextHostKeyHandle = hostKeyHandle
        }
  KeyExchange.runKex keyExchangeHandle kexContext recv send

doAlgorithmNegotiation ::
     [HostKey.ServerHandle]
  -> [KeyExchange.ServerHandle]
  -> ([Word8] -> IO SshRawPacket)
  -> (SshPacket -> IO ())
  -> IO (HostKey.ServerHandle, KeyExchange.ServerHandle, SshClientServer SshRawPacket)
doAlgorithmNegotiation hostKeyHandles keyExchangeHandles recv send = do
  putStrLn "Starting Algorithm Negotiation"
  let ourNegotiationSet = buildNegotiationSet
  kexInitRawPacketSent <- sendSshMsgKexInit ourNegotiationSet
  (kexInitRawPacketReceived, theirNegotiationSet, followingPacket) <- receiveSshMsgKexInit
  discardFollowingPacketWhenGuessIsWrong followingPacket ourNegotiationSet theirNegotiationSet
  let result = negotiateAlgorithms ourNegotiationSet theirNegotiationSet
  putStrLn $ "Result: " ++ show result
  maybe (error "No algorithm found") return $
    fmap (\(a, b) -> (a, b, SshClientServer kexInitRawPacketReceived kexInitRawPacketSent)) result
  where
    buildNegotiationSet :: NegotiationSet
    buildNegotiationSet =
      NegotiationSet
      { kexAlgs = KeyExchange.name <$> keyExchangeHandles
      , serverHostKeyAlgs = HostKey.name <$> hostKeyHandles
      , encryptionAlgs = BiDirectional tempEncryptionAlgs tempEncryptionAlgs
      , macAlgs = BiDirectional tempMacAlgs tempMacAlgs
      , compressionAlgs = BiDirectional tempCompressionAlgs tempCompressionAlgs
      , languages = BiDirectional tempLanguages tempLanguages
      }
    guessIsWrong :: NegotiationSet -> NegotiationSet -> Bool
    guessIsWrong ourNegotiationSet theirNegotiationSet = head (kexAlgs ourNegotiationSet) /= head (kexAlgs theirNegotiationSet)
    sendSshMsgKexInit :: NegotiationSet -> IO SshRawPacket
    sendSshMsgKexInit negotiationSet = do
      let kexInitPacket = mkSshPacketKexInit newCookie negotiationSet
      send kexInitPacket
      putStrLn "SSH_MSG_KEXINIT Sent"
      return $ toSshRawPacket kexInitPacket
    receiveSshMsgKexInit :: IO (SshRawPacket, NegotiationSet, Bool)
    receiveSshMsgKexInit = do
      kexInitRawPacketReceived <- recv [c_SSH_MSG_KEXINIT]
      let (_, theirNegotiationSet, followingPacket) = readKexInitPacket kexInitRawPacketReceived
      putStrLn "SSH_MSG_KEXINIT Received"
      return (kexInitRawPacketReceived, theirNegotiationSet, followingPacket)
    discardFollowingPacketWhenGuessIsWrong :: Bool -> NegotiationSet -> NegotiationSet -> IO ()
    discardFollowingPacketWhenGuessIsWrong followingPacket ourNegotiationSet theirNegotiationSet =
      when
        (followingPacket && guessIsWrong ourNegotiationSet theirNegotiationSet)
        (void $ recv [30 .. 49]) -- Discard the next packet
    negotiateAlgorithms :: NegotiationSet -> NegotiationSet -> Maybe (HostKey.ServerHandle, KeyExchange.ServerHandle)
    negotiateAlgorithms serverNegotiationSet clientNegotiationSet = do
      keyExchangeHandle <-
        if guessIsWrong serverNegotiationSet clientNegotiationSet
          then negotiateKexAlgorithm clientNegotiationSet
          else find (\handle -> KeyExchange.name handle == head (kexAlgs serverNegotiationSet)) keyExchangeHandles
      hostKeyHandle <- negotiateHostKeyAlgorithm clientNegotiationSet keyExchangeHandle
      return (hostKeyHandle, keyExchangeHandle)
    negotiateKexAlgorithm :: NegotiationSet -> Maybe KeyExchange.ServerHandle
    negotiateKexAlgorithm clientNegotiationSet =
      let supportedKexHandles =
            catMaybes $
            fmap (\name -> find (\handle -> KeyExchange.name handle == name) keyExchangeHandles) (kexAlgs clientNegotiationSet)
      in find (isJust . negotiateHostKeyAlgorithm clientNegotiationSet) supportedKexHandles
    negotiateHostKeyAlgorithm :: NegotiationSet -> KeyExchange.ServerHandle -> Maybe HostKey.ServerHandle
    negotiateHostKeyAlgorithm clientNegotiationSet kexHandle =
      let supportedHostKeyHandles =
            catMaybes $
            fmap (\name -> find (\handle -> HostKey.name handle == name) hostKeyHandles) (serverHostKeyAlgs clientNegotiationSet)
      in find isValidKexAlgorithm supportedHostKeyHandles
      where
        isValidKexAlgorithm :: HostKey.ServerHandle -> Bool
        isValidKexAlgorithm hostKeyHandle =
          (not (KeyExchange.requiresHostKeyEncryptionCapable kexHandle) || isJust (HostKey.encrypt hostKeyHandle)) &&
          (not (KeyExchange.requiresHostKeySignatureCapable kexHandle) || isJust (HostKey.sign hostKeyHandle))

findFirst :: (a -> Bool) -> [a] -> Maybe a
findFirst _ [] = Nothing
findFirst cond (x:xs) =
  if cond x
    then Just x
    else findFirst cond xs

exists :: (a -> Bool) -> [a] -> Bool
exists cond list = isJust $ find cond list

readKexInitPacket :: SshRawPacket -> (Cookie, NegotiationSet, Bool)
readKexInitPacket packet = runGet readNegotiationGet $ LBS.fromStrict $ sshRawPacketPayload packet
  where
    readNegotiationGet :: Get (Cookie, NegotiationSet, Bool)
    readNegotiationGet = do
      cookie <- fmap MkCookie (getByteString 16)
      list1 <- getNameList
      list2 <- getNameList
      list3 <- getNameList
      list4 <- getNameList
      list5 <- getNameList
      list6 <- getNameList
      list7 <- getNameList
      list8 <- getNameList
      list9 <- getNameList
      list10 <- getNameList
      firstKexPacketFollows <- getBoolean
      getInt32be -- the last uint32 ignored
      let negotiationSet = NegotiationSet {kexAlgs = list1, serverHostKeyAlgs = list2, encryptionAlgs = BiDirectional list3 list4}
      return (cookie, negotiationSet, firstKexPacketFollows)

getNameList :: Get [ByteString]
getNameList = do
  nameListLength <- fmap fromIntegral getWord32be
  listWithCommas <- getByteString nameListLength
  return $ C8.split ',' listWithCommas

getBoolean :: Get Bool
getBoolean = do
  value <- getWord8
  if value == 0
    then return False
    else return True
