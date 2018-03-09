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

module Network.Yassh.Internal.KeyExchange.DiffieHellman
  (
  ) where

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.PubKey.DH
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Proxy (Proxy(Proxy))
import Data.Word (Word8)
import Development.Placeholders
import Network.Yassh.Internal
