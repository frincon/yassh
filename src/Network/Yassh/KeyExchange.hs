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
{-# LANGUAGE ExistentialQuantification #-}

module Network.Yassh.KeyExchange
  ( 
  ) where

import Control.Monad (void, when)
import Crypto.Hash
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Data.Binary.Get
       (Get, getByteString, getInt32be, getRemainingLazyByteString,
        getWord32be, getWord8, runGet, runGetIncremental)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Either (either)
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy(Proxy))
import Data.Word8 (Word8)
import Development.Placeholders
import Network.Yassh.Internal
import Network.Yassh.Internal.KeyExchange
import Network.Yassh.Internal.KeyExchange.DiffieHellman --TODO This should not be here
