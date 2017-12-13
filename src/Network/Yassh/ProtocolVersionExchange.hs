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

module Network.Yassh.ProtocolVersionExchange
  ( runProtocolVersionExchange
  -- TODO Those are for testing, refactor testing to not have to go to this
  -- detailed functions
  , bannerLines
  , receiveBanner
  ) where

import Network.Yassh.Internal

import Control.Applicative ((<|>))
import Data.Word8 (_hyphen, _space)

import Control.Concurrent.Async (concurrently)
import Data.Attoparsec.ByteString
       (Parser, anyWord8, manyTill, string, takeWhile1, word8)
import Data.Attoparsec.Combinator (lookAhead)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Version (showVersion)

import Data.Maybe (fromMaybe)
import System.IO.Streams (InputStream, OutputStream)
import qualified System.IO.Streams as Streams
import System.IO.Streams.Attoparsec.ByteString (parseFromStream)

supportedProtocolVersion = "2.0"

runProtocolVersionExchange :: (InputStream ByteString, OutputStream ByteString) -> SshRole -> SshSettings -> IO SshVersion
runProtocolVersionExchange (is, os) role settings =
  snd <$>
  concurrently -- TODO Make sense concurrently?
    (sendIdentificationString (sshSettingsVersion settings) os)
    (receiveIdentificationString is role settings)

receiveIdentificationString :: InputStream ByteString -> SshRole -> SshSettings -> IO SshVersion
receiveIdentificationString is role settings = do
  case role of
    SshRoleClient -> do
      banner <- receiveBanner is
      sshSettingsOnReceiveBanner settings banner
    SshRoleServer -> return ()
  receiveAndCheckIdentificationString is

-- TODO Use SshVersion to output as well
sendIdentificationString :: SshVersion -> OutputStream ByteString -> IO ()
sendIdentificationString sshVersion = Streams.write (Just $ BS.append (toIdentificationString sshVersion) "\r\n")

receiveBanner :: InputStream ByteString -> IO ByteString
receiveBanner = parseFromStream bannerLines

bannerLines :: Parser ByteString
bannerLines =
  lookAhead (string "SSH-") *> return "" <|> do
    banner <- BS.pack <$> manyTill anyWord8 (string "\r\n" *> lookAhead (string "SSH-"))
    return $ BS.append banner "\r\n"

receiveAndCheckIdentificationString :: InputStream ByteString -> IO SshVersion
receiveAndCheckIdentificationString is = do
  version <- parseFromStream sshVersionParser is
  if protocolVersion version /= supportedProtocolVersion
    then fail $ "Protocol Version not Supported: " ++ show version
    else return version

sshVersionParser :: Parser SshVersion
sshVersionParser = do
  string "SSH-"
  protocolVersion <- takeWhile1 (/= _hyphen)
  word8 _hyphen
  (softwareVersion, comments) <- (BS.break (== _space) . BS.pack) <$> manyTill anyWord8 (string "\r\n")
  return
    SshVersion
    { protocolVersion = protocolVersion
    , softwareVersion = softwareVersion
    , comments =
        if BS.null comments
          then Nothing
          else Just $ BS.drop 1 comments
    }
