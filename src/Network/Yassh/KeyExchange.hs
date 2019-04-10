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
  ( KexServerContext(..)
  , ServerHandle(..)
  ) where

import Data.ByteString (ByteString)
import Data.ByteString.Char8 (unpack)
import Data.Word (Word8)
import qualified Network.Yassh.HostKey as HostKey
import Network.Yassh.Internal

data KexServerContext = KexContext
  { kexContextIdentificationString :: SshClientServer ByteString
  , kexContextMsgInit :: SshClientServer SshRawPacket
  , kexContextHostKeyHandle :: HostKey.ServerHandle
  }

data ServerHandle = ServerHandle
  { name :: ByteString
  , requiresHostKeyEncryptionCapable :: Bool
  , requiresHostKeySignatureCapable :: Bool
  , runKex :: KexServerContext -> ([Word8] -> IO SshRawPacket) -> (SshPacket -> IO ()) -> IO (ByteString, ByteString)
  }

instance Show ServerHandle where
  show handle = "KeyExchange.ServerHandle { name = " ++ unpack (name handle) ++ "}"
