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
{-# LANGUAGE ExistentialQuantification #-}

module Network.Yassh.Internal.KeyExchange
  ( KexContext(..)
  , Named(..)
  , KexAlgorithm(..)
  , HostKeyAlgorithm(..)
  , EncryptionAlgorithm(..)
  , MacAlgorithm(..)
  , CompressionAlgorithm(..)
  , Language(..)
  , KexResult(..)
  ) where

import Data.ByteArray (ByteArray)
import Data.ByteString (ByteString)
import Data.Function (on)
import Data.Word (Word8)
import Network.Yassh.Internal

data KexContext = KexContext
  { kexContextIdentificationString :: SshClientServer ByteString
  , kexContextMsgInit :: SshClientServer SshRawPacket
  , kexContextHostKeyAlgorithm :: HostKeyAlgorithm
  , kexContextHostKeyEncoded :: ByteString
  , kexContextSign :: ByteString -> ByteString
  }

class Named a where
  nameAsBytestring :: a -> ByteString

data KexResult = KexResult
  { kexResultExchangeHash :: ByteString
  , kexResultSharedKey :: ByteString
  }

data KexAlgorithm = KexAlgorithm
  { kexAlgorithmName :: ByteString
  , requiresEncryptionCapable :: Bool
  , requiresSignatureCapable :: Bool
  , runKex :: SshRole -> KexContext -> ([Word8] -> IO SshRawPacket) -> (SshPacket -> IO ()) -> IO KexResult
  , hash :: ByteString -> ByteString
  }

instance Named KexAlgorithm where
  nameAsBytestring = kexAlgorithmName

data HostKeyAlgorithm = HostKeyAlgorithm
  { hostKeyAlgorithmName :: ByteString
  , isEncryptionCapable :: Bool
  , isSignatureCapable :: Bool
  } deriving (Eq, Show)

instance Show KexAlgorithm where
  show a = "KexAlgorithm " ++ (show $ kexAlgorithmName a)

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
