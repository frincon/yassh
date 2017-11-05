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

module Network.Yassh.IOStreams
  ( runSshServer
  )
where

import System.IO.Streams (InputStream, OutputStream)
import qualified System.IO.Streams as Streams
import Data.ByteString (ByteString)
import Network.Socket (PortNumber)
import Development.Placeholders
import qualified Network.Yassh as Yassh

runSshServer :: PortNumber -> ((InputStream ByteString, OutputStream ByteString) -> IO ()) -> IO ()
runSshServer port shellIO = Yassh.runSshServer port $ \(receive, send, sendErr) -> do
  is <- Streams.makeInputStream receive
  os <- Streams.makeOutputStream $ \maybeBytes -> case maybeBytes of
    Just bytes -> send bytes
    Nothing -> return ()
  shellIO (is, os)
