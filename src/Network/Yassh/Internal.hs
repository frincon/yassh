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
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}

module Network.Yassh.Internal
  ( SshRole(..)
  , SshVersion(..)
  , SshSettings(..)
  , SshContext(..)
  , SshAction(..)
  , SshPacket(..)
  , SshRawPacket(..)
  , SshData(..)
  , SshClientServer(..)
  , ToSshPacket(..)
  , FromSshRawPacket(..)
  , ToSshRawPacket(..)
  , c_SSH_MSG_KEXINIT
  , c_SSH_MSG_IGNORE
  , c_SSH_MSG_KEXDH_INIT
  , c_SSH_MSG_KEXDH_REPLY
  , fromRole
  , roleBased
  , toIdentificationString
  , sshRawPacketPayload
  , getMPint
  , sshEncode
  , i2bs
  , bs2i
  ) where

import Control.Monad.Reader (ReaderT)
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.Binary.Put
import Data.Bits (shiftL, shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Int (Int64)
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy)
import Data.Time.TimeSpan (TimeSpan)
import Data.Word (Word32, Word8)
import System.IO.Streams (InputStream, OutputStream)

data SshRole
  = SshRoleClient
  | SshRoleServer

data SshVersion = SshVersion
  { protocolVersion :: ByteString
  , softwareVersion :: ByteString
  , comments :: Maybe ByteString
  } deriving (Eq, Show)

data SshSettings = MkSshSettings
  { sshSettingsOnProtocolVersionExchange :: SshVersion -> IO ()
  , sshSettingsOnReceiveBanner :: ByteString -> IO ()
  , sshSettingsProtocolVersionExchangeSizeLimitBytes :: Int64
  , sshSettingsIgnoreInterval :: TimeSpan
  , sshSettingsVersion :: SshVersion
  , sshSettingsKexProtocolsAllowed :: [ByteString]
  }

data SshContext = MkSshContext
  { sshContextRole :: SshRole
  , sshContextStreams :: (InputStream ByteString, OutputStream ByteString)
  , sshContextSettings :: SshSettings
  , sshContextPeerVersion :: SshVersion
  , sshContextPacketStreams :: (InputStream SshRawPacket, OutputStream SshPacket)
  }

type SshAction = ReaderT SshContext

data SshPacket =
  SshPacket Word8
            [SshData]

data SshRawPacket =
  SshRawPacket Word8
               ByteString

sshRawPacketPayload :: SshRawPacket -> ByteString
sshRawPacketPayload (SshRawPacket _ payload) = payload

data SshData
  = SshString ByteString
  | SshBoolean Bool
  | SshByte Word8
  | SshByteArray Word8
                 ByteString
  | SshNameList [ByteString]
  | SshUInt32 Word32
  | SshMPint Integer

class ToSshPacket t where
  toSshPacket :: t -> SshPacket

class FromSshRawPacket t where
  fromSshRawPacket :: SshRawPacket -> t
  expectedMsgId :: Proxy t -> Word8

class ToSshRawPacket t where
  toSshRawPacket :: t -> SshRawPacket

instance ToSshRawPacket SshPacket where
  toSshRawPacket (SshPacket msgId otherData) = SshRawPacket msgId $ LBS.toStrict $ runPut $ mapM_ dataToPut otherData
    where
      dataToPut :: SshData -> Put
      dataToPut (SshString payload) = do
        putWord32be $ fromIntegral $ BS.length payload
        putByteString payload
      dataToPut (SshBoolean True) = putWord8 1
      dataToPut (SshBoolean False) = putWord8 0
      dataToPut (SshByte b) = putWord8 b
      dataToPut (SshByteArray _ payload) = putByteString payload -- TODO Check for the same length that expectged
      dataToPut (SshNameList nameList) = do
        let listAsByteString = BS.intercalate "," nameList
        putWord32be $ fromIntegral $ BS.length listAsByteString
        putByteString listAsByteString
      dataToPut (SshUInt32 b) = putWord32be b
      dataToPut (SshMPint i) = do
        putWord32be $ fromIntegral $ BS.length $ i2bs i
        putByteString $ i2bs i

-- TODO Refactor this, it is little bit ugly
sshEncode :: [SshData] -> ByteString
sshEncode p = sshRawPacketPayload $ toSshRawPacket $ SshPacket 0 p

c_SSH_MSG_KEXINIT = 20 :: Word8

c_SSH_MSG_IGNORE = 2 :: Word8

c_SSH_MSG_KEXDH_INIT = 30 :: Word8

c_SSH_MSG_KEXDH_REPLY = 31 :: Word8

data SshClientServer t = SshClientServer
  { clientData :: t
  , serverData :: t
  }

instance Functor SshClientServer where
  fmap f SshClientServer {clientData = clientData, serverData = serverData} = SshClientServer (f clientData) (f serverData)

fromRole :: SshRole -> t -> t -> SshClientServer t
fromRole SshRoleClient local remote = SshClientServer {clientData = local, serverData = remote}
fromRole SshRoleServer local remote = SshClientServer {clientData = remote, serverData = local}

toIdentificationString :: SshVersion -> ByteString
toIdentificationString sshVersion =
  BS.concat ["SSH-", protocolVersion sshVersion, "-", softwareVersion sshVersion, maybe "" (BS.append " ") (comments sshVersion)]

roleBased :: SshRole -> a -> a -> a
roleBased SshRoleServer server _ = server
roleBased SshRoleClient _ client = client

getMPint :: Get Integer
getMPint = do
  mpLength <- getWord32be
  if mpLength == 0
    then return 0
    else do
      intAsTwoComplement <- getByteString (fromIntegral mpLength)
      return $ bs2i intAsTwoComplement

-- Copied and modified from https://stackoverflow.com/questions/15047191/read-write-haskell-integer-in-twos-complement-representation
bs2i :: ByteString -> Integer
bs2i b
  | sign = go b - 2 ^ (BS.length b * 8)
  | otherwise = go b
  where
    go = BS.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0
    sign = BS.index b 0 > 127

i2bs :: Integer -> ByteString
i2bs x
  | x == 0 = ""
  | x < 0 = i2bs $ 2 ^ (8 * bytes) + x
  | otherwise =
    if (BS.index positive 0) > 127
      then BS.append (BS.singleton 0) positive
      else positive
  where
    bytes = (integerLogBase 2 (abs x) + 1) `quot` 8 + 1
    positive = BS.reverse $ BS.unfoldr go x
    go i =
      if i == 0
        then Nothing
        else Just (fromIntegral i, i `shiftR` 8)

integerLogBase :: Integer -> Integer -> Int
integerLogBase b i =
  if i < b
    then 0
        -- Try squaring the base first to cut down the number of divisions.
    else let l = 2 * integerLogBase (b * b) i
             doDiv :: Integer -> Int -> Int
             doDiv i l =
               if i < b
                 then l
                 else doDiv (i `div` b) (l + 1)
         in doDiv (i `div` (b ^ l)) l
