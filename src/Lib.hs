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

module Lib
  ( -- testServer
  ) where

import Network.Socket hiding (recv, send)
import Network.Socket.ByteString (send)
import Network.Yassh (supportedKexSet, newCookie, readPacket, readKexPacket, algorithmNegotiation)
import System.IO
import qualified System.IO.Streams as Streams
import System.IO.Streams.Network (socketToStreams)

-- testServer :: IO ()
-- testServer = do
--   putStrLn "Listening"
--   hFlush stdout
--   sock <- socket AF_INET Stream 0 -- create socket
--   setSocketOption sock ReuseAddr 1 -- make socket immediately reusable - eases debugging.
--   bind sock (SockAddrInet 2222 iNADDR_ANY) -- listen on TCP port 4242.
--   listen sock 2 -- set a max of 2 queued connections
--   mainLoop sock -- unimplemented
--
-- mainLoop :: Socket -> IO ()
-- mainLoop sock = do
--   conn <- accept sock
--   putStrLn "accepted connection"
--   hFlush stdout
--   runConn conn
--   mainLoop sock
--
-- runConn :: (Socket, SockAddr) -> IO ()
-- runConn (sock, _) = do
--   putStrLn "New connection"
--   hFlush stdout
--   (is, os) <- socketToStreams sock
--   putStrLn "Streams opened"
--   hFlush stdout
--   version <- protocolVersionExchangeServer (is, os)
--   print version
--   hFlush stdout
--   sendKexInitPacket supportedKexSet newCookie os
--   kexResult <- readPacket is readKexPacket
--   print kexResult
--   let (kexAlg, hostAlg, _, _, _) = algorithmNegotiation (snd kexResult) supportedKexSet
--   print kexAlg
--   print hostAlg
--   go is
--   where
--     go is = do
--       nextBytes <- Streams.read is
--       case nextBytes of
--         Just bytes -> do
--           print bytes
--           hFlush stdout
--           go is
--         Nothing -> return ()
--
