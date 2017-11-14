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
module Network.Yassh.Internal
  ( SshRole(..)
  , SshVersion(..)
  , SshSettings(..)
  , SshContext(..)
  , SshClientContext(..)
  , SshServerContext(..)
  , SshAction(..)
  , SshPacket(..)
  , SshRawPacket(..)
  , SshData(..)
  ) where

import Control.Monad.Reader (ReaderT)
import Data.ByteString (ByteString)
import Data.Word (Word8)
import Data.Int (Int64)
import Data.Time.TimeSpan (TimeSpan)
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
  }

data SshContext t = MkSshContext
  { sshContextSpecificContext :: t
  , sshContextRole :: SshRole
  , sshContextStreams :: (InputStream ByteString, OutputStream ByteString)
  , sshContextSettings :: SshSettings
  , sshContextPeerVersion :: Maybe SshVersion
  , sshContextPacketStreams :: Maybe (InputStream SshRawPacket, OutputStream SshPacket)
  }

data SshClientContext =
  MkSshClientContext

data SshServerContext =
  MkSshServerContext

type SshAction t = ReaderT (SshContext t)

data SshPacket =
  SshPacket Word8
            [SshData]

data SshRawPacket =
  SshRawPacket Word8
               ByteString

data SshData
  = SshString ByteString
  | SshBoolean Bool
