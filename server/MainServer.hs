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

import Network.Yassh.IOStreams
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import System.IO (hSetBuffering, BufferMode(NoBuffering), stdout)
import System.IO.Streams (InputStream, OutputStream)
import qualified System.IO.Streams as Streams

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  runSshServer 2022 dummyShell

dummyShell :: (InputStream ByteString, OutputStream ByteString) -> IO ()
dummyShell (is, os) = do
  isLines <- Streams.lines is -- TODO This is not safe as can blow up the memory if there is no end of line
  loop (isLines, os)
  where
    loop (is, os) =  do
      maybeLine <- Streams.read is
      case maybeLine of
        Just line -> do
          Streams.write (Just $ BS.concat ["I can't understand '", line, "'\n"]) os
          loop (is, os)
        Nothing -> Streams.write Nothing os
