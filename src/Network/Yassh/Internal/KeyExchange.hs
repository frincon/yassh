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
  , runAlgorithmNegotiation
  , resolveAlgorithms
  , NegotiationSet(..)
  , NegotiationResult(..)
  ) where

import Control.Monad (void, when)
import Crypto.Hash
import Data.Function (on)

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.PubKey.DH
import Crypto.Random

-- import Crypto.PubKey.RSA
-- import Crypto.PubKey.RSA.PKCS15
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGetOrFail, runGetIncremental, ByteOffset)
import Data.ByteArray (convert)
import Data.Int (Int64)
import Data.List.NonEmpty (NonEmpty)
import Data.Bifunctor (first)
import qualified Data.List.NonEmpty as NE
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy as LBS
import Data.Either (either)
import Data.List (find, intersect)
import Control.Concurrent.Async (concurrently)
import Data.Maybe (catMaybes, fromMaybe, isJust, maybe)
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
  { kexAlgs :: NonEmpty ByteString
  , serverHostKeyAlgs :: NonEmpty ByteString
  , encryptionAlgs :: BiDirectional (NonEmpty ByteString)
  , macAlgs :: BiDirectional (NonEmpty ByteString)
  , compressionAlgs :: BiDirectional (NonEmpty ByteString)
  , languages :: BiDirectional [ByteString]
  }
  deriving (Show, Eq)

data NegotiationResult = 
  NegotiationResult 
    { kexAlgo :: ByteString
    , serverHostKeyAlgo :: ByteString
    , encryptionAlgo :: BiDirectional ByteString
    , macAlgo :: BiDirectional ByteString
    , compressionAlgo :: BiDirectional ByteString
    , language :: BiDirectional ByteString
    }
  deriving (Show, Eq)

resolveAlgorithms :: (ByteString -> ByteString -> Bool) -> BiDirectional NegotiationSet -> Either String NegotiationResult
resolveAlgorithms isKexCompatible (BiDirectional clientSet serverSet) = 
  let
    intersect' func = intersect (func clientSet) (func serverSet) 
    kex'' = intersect' (NE.toList . kexAlgs)
    kex' = filter (\kexAlgo -> any (isKexCompatible kexAlgo) key') kex''
    key' = intersect' (NE.toList . serverHostKeyAlgs)
    encCtoS' = intersect' (NE.toList . clientToServer . encryptionAlgs)
    encStoC' = intersect' (NE.toList . serverToClient . encryptionAlgs)
    macCtoS' = intersect' (NE.toList . clientToServer . macAlgs)
    macStoC' = intersect' (NE.toList . serverToClient . macAlgs)
    compCtoS' = intersect' (NE.toList . clientToServer . compressionAlgs)
    compStoC' = intersect' (NE.toList . serverToClient . compressionAlgs)
    
    firstOrFail errorMessage [] = Left errorMessage
    firstOrFail _ (x:xs) = Right x
  in do
    kex <- if NE.head (kexAlgs clientSet) == NE.head (kexAlgs serverSet)
      then Right $ NE.head (kexAlgs clientSet)
      else firstOrFail "No Key Exchange Algorithm compatible" kex'
    key <- firstOrFail "No Host Key Algorithm compatible" $ filter (\k -> isKexCompatible kex k) key'
    encCtoS <- firstOrFail "No Encryption Algorithm Client to Server compatible" $ encCtoS'
    encStoC <- firstOrFail "No Encryption Algorithm Server to Client compatible" $ encStoC'
    macCtoS <- firstOrFail "No MAC Algorithm Client to Server compatible" $ macCtoS'
    macStoC <- firstOrFail "No MAC Algorithm Server to Client compatible" $ macStoC'
    compCtoS <- firstOrFail "No Compression Algorithm Client to Server compatible" $ compCtoS'
    compStoC <- firstOrFail "No Compression Algorithm Server to Client compatible" $ compStoC'

    return $ 
      NegotiationResult kex key (BiDirectional encCtoS encStoC) (BiDirectional macCtoS macStoC) (BiDirectional compCtoS compStoC) (BiDirectional "" "")

runAlgorithmNegotiation :: 
     ([Word8] -> IO SshRawPacket) 
  -> (SshPacket -> IO ())
  -> (BiDirectional NegotiationSet -> Either String NegotiationResult)
  -> NegotiationSet
  -> IO NegotiationResult
runAlgorithmNegotiation recv send negotiate negotiationSet = do
  (recvResult, _) <- concurrently recvSshMsgKexinit sendSshMsgKexinit
  case recvResult of
    Left errorMessage -> fail errorMessage
    Right (_, clientNegotiationSet, following) -> do
      let negotiationSets = BiDirectional clientNegotiationSet negotiationSet
      when (guessIsWrong negotiationSets && following) discardPacket
      case  negotiate $ BiDirectional clientNegotiationSet negotiationSet of
        Left errorMsg -> fail errorMsg
        Right a -> return a
    where
      discardPacket = void $ recv [30..49] -- TODO Change to constant
      recvSshMsgKexinit = readKexInitPacket <$> recv [c_SSH_MSG_KEXINIT]
      sendSshMsgKexinit = do
        cookie <- newCookie
        send $ mkSshPacketKexInit cookie negotiationSet
      guessIsWrong (BiDirectional ctos stoc) = NE.head (kexAlgs ctos) /= NE.head (kexAlgs stoc)
  
runKeyExchangeServer ::
     [HostKey.ServerHandle]
  -> [KeyExchange.ServerHandle]
  -> SshClientServer SshVersion
  -> ([Word8] -> IO SshRawPacket)
  -> (SshPacket -> IO ())
  -> IO ()
runKeyExchangeServer hostKeyHandlers keyExchangeHandles versions recv send = $notImplemented

newCookie :: IO Cookie
newCookie = MkCookie <$> getRandomBytes 16

-- TODO Support following first paket?
mkSshPacketKexInit :: Cookie -> NegotiationSet -> SshPacket
mkSshPacketKexInit (MkCookie cookieBytes) negotiationSet =
  SshPacket
    c_SSH_MSG_KEXINIT
    [ SshByteArray 16 cookieBytes
    , SshNameList $ NE.toList $ kexAlgs negotiationSet
    , SshNameList $ NE.toList $ serverHostKeyAlgs negotiationSet
    , SshNameList $ NE.toList $ clientToServer $ encryptionAlgs negotiationSet
    , SshNameList $ NE.toList $ serverToClient $ encryptionAlgs negotiationSet
    , SshNameList $ NE.toList $ clientToServer $ macAlgs negotiationSet
    , SshNameList $ NE.toList $ serverToClient $ macAlgs negotiationSet
    , SshNameList $ NE.toList $ clientToServer $ compressionAlgs negotiationSet
    , SshNameList $ NE.toList $ serverToClient $ compressionAlgs negotiationSet
    , SshNameList $ clientToServer $ languages negotiationSet
    , SshNameList $ serverToClient $ languages negotiationSet
    , SshBoolean False
    , SshUInt32 0 -- Future use
    ]

readKexInitPacket :: SshRawPacket -> Either String (Cookie, NegotiationSet, Bool)
readKexInitPacket packet = first mapError $ runGet' readNegotiationGet $ packet
  where

    mapError :: (LBS.ByteString, ByteOffset, String)  -> String
    mapError (_, offset, errorMessage) = "Invalid SSH_MSG_KEXINIT at " ++ show offset ++ ": " ++ errorMessage 

    readNegotiationGet :: Get (Cookie, NegotiationSet, Bool)
    readNegotiationGet = do
      cookie <- MkCookie <$> (getByteString 16)
      list1 <- getNonEmptyNameList
      list2 <- getNonEmptyNameList
      list3 <- getNonEmptyNameList
      list4 <- getNonEmptyNameList
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

runGet' :: Get a -> SshRawPacket -> Either (LBS.ByteString, ByteOffset, String) a 
runGet' parser packet = 
  let result = runGetOrFail parser $ LBS.fromStrict $ sshRawPacketPayload packet
  in
    case result of
      Left err -> Left err
      Right (remain, offset, result') -> 
        if LBS.null remain
          then Right result'
          else Left (remain, offset, "Not all data has been consumed") -- TODO This should happen for all the packets? Needs to go to a level up?

getNameList :: Get [ByteString]
getNameList = do
  nameListLength <- fmap fromIntegral getWord32be
  listWithCommas <- getByteString nameListLength
  return $ C8.split ',' listWithCommas

getNonEmptyNameList :: Get (NonEmpty ByteString)
getNonEmptyNameList = do
  nameListLength <- fromIntegral <$> getWord32be
  if nameListLength == 0
    then fail "Non Empty list expected, empty list received"
    else (NE.fromList . C8.split ',') <$> getByteString nameListLength

getBoolean :: Get Bool
getBoolean = do
  value <- getWord8
  if value == 0
    then return False
    else return True
