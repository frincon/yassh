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

import Control.Monad.IO.Class (liftIO)
import Data.Attoparsec.ByteString
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Network.Yassh
import Network.Yassh.Internal
import Network.Yassh.Internal.ProtocolVersionExchange
import qualified System.IO.Streams as Streams
import System.IO.Streams.ByteString (fromByteString)
import Test.Hspec

import qualified Network.Yassh.HostKey.SshRsaSpec
import qualified Network.Yassh.Internal.KeyExchange.DiffieHellmanSpec

-- TODO Make a memory test for large banners
main :: IO ()
main =
  hspec $
    {- 
    describe "Network.Yassh.bannerLines" $ do
      it "Returns nothing when the line start with SSH-" $ do parseOnly bannerLines "SSH-PEpito" `shouldBe` Right ""
      it "Does not consume the SSH- part" $ do parse bannerLines "SSH-Pepito" `shouldSatisfy` leavesUnconsumed "SSH-Pepito"
      it "Consumes multiple lines" $ do
        parse bannerLines "Banner1\r\nBanner2\r\nSSH-Pepito" `shouldSatisfy`
          doneWithResultAndUnconsumed "Banner1\r\nBanner2\r\n" "SSH-Pepito"
    describe "Network.Yassh.receiveBanner" $ do
      it "Remain the inputstream with the SSH-" $ do
        is <- liftIO $ fromByteString "SSH-Pepito"
        liftIO $ receiveBanner is
        Streams.read is `shouldReturn` Just "SSH-Pepito"
      it "Consume all the banner files" $ do
        is <- liftIO $ fromByteString "Banner1\r\nBanner2\r\nSSH-Pepito"
        liftIO $ receiveBanner is
        Streams.read is `shouldReturn` Just "SSH-Pepito"
      it "Can Continue" $ do
        is <- liftIO $ Streams.fromList ["Banner1\r\n", "Bann", "er2\r\nSSH-Pepito"]
        liftIO $ receiveBanner is
        Streams.read is `shouldReturn` Just "SSH-Pepito"
      it "Should fail if the stream is exhausted" $ do
        is <- liftIO $ Streams.fromList ["Banner1\r\n", "Bann", "er2\r\nOther Banner"]
        receiveBanner is `shouldThrow` anyException -- TODO make it explicit
    -}
   do
    Network.Yassh.HostKey.SshRsaSpec.spec
    Network.Yassh.Internal.KeyExchange.DiffieHellmanSpec.spec
    describe "Network.Yassh.runProtocolVersionExchange" $ do
      it "Should return the correct version without comments and wothout banner" $ do
        is <- liftIO $ Streams.fromByteString "SSH-2.0-test\r\n"
        os <- liftIO $ Streams.makeOutputStream (\input -> return ())
        runProtocolVersionExchange (is, os) SshRoleClient defaultClientSettings `shouldReturn`
          SshVersion {protocolVersion = "2.0", softwareVersion = "test", comments = Nothing}
      it "Should return the correct version with comments and without banner" $ do
        is <- liftIO $ Streams.fromByteString "SSH-2.0-test  this is a comment \r\n"
        os <- liftIO $ Streams.makeOutputStream (\input -> return ())
        runProtocolVersionExchange (is, os) SshRoleClient defaultClientSettings `shouldReturn`
          SshVersion {protocolVersion = "2.0", softwareVersion = "test", comments = Just " this is a comment "}
      it "Should return the correct version with empty comment and without banner" $ do
        is <- liftIO $ Streams.fromByteString "SSH-2.0-test \r\n"
        os <- liftIO $ Streams.makeOutputStream (\input -> return ())
        runProtocolVersionExchange (is, os) SshRoleClient defaultClientSettings `shouldReturn`
          SshVersion {protocolVersion = "2.0", softwareVersion = "test", comments = Just ""}
      it "Should return the correct version with comment and banner" $ do
        is <- liftIO $ Streams.fromByteString "banner1\r\nbanner2\r\nSSH-2.0-test  this is a comment \r\n"
        os <- liftIO $ Streams.makeOutputStream (\input -> return ())
        runProtocolVersionExchange (is, os) SshRoleClient defaultClientSettings `shouldReturn`
          SshVersion {protocolVersion = "2.0", softwareVersion = "test", comments = Just " this is a comment "}

leavesUnconsumed :: ByteString -> Result r -> Bool
leavesUnconsumed expected (Done unconsummed _) = expected == unconsummed
leavesUnconsumed _ _ = False

doneWithResultAndUnconsumed :: Eq r => r -> ByteString -> Result r -> Bool
doneWithResultAndUnconsumed expectedResult expectedUnconsummed (Done unconsummed result) =
  expectedResult == result && expectedUnconsummed == unconsummed
