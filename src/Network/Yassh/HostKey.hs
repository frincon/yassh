-- Copyright 2018 Fernando Rincon Martin
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
module Network.Yassh.HostKey
  ( ServerHandle(..)
  , Sign
  , Encrypt
  , isEncryptionCapable
  , isSignatureCapable
  )
where

import Data.ByteString (ByteString)
import Data.ByteString.Char8 (unpack)
import Network.Yassh.Internal
import Data.Maybe (isJust)

type Sign = ByteString -> ByteString
type Encrypt = ByteString -> ByteString

data ServerHandle = ServerHandle
  { name :: ByteString
  , sign :: Maybe Sign
  , encrypt :: Maybe Encrypt
  , encodedKey :: ByteString
  }

isEncryptionCapable :: ServerHandle -> Bool
isEncryptionCapable = isJust . encrypt

isSignatureCapable :: ServerHandle -> Bool
isSignatureCapable = isJust . sign

instance Show ServerHandle where
  show handle = "HostKey.ServerHandle { name = " ++ unpack (name handle) ++"}"
