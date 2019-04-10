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
{-# LANGUAGE TemplateHaskell #-}
module Network.Yassh.HostKey.SshRsaSpec
(
  spec
)
where

import Crypto.Hash (SHA1(..))
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import Development.Placeholders
import Test.Hspec
import Crypto.Random
import Data.Maybe (isJust, fromJust)
import Data.Either (fromRight)

import Network.Yassh.HostKey
import Network.Yassh.HostKey.SshRsa
import Network.Yassh.Internal


givenConfiguration :: Configuration
givenConfiguration = Configuration givenPrivateKey

drg = drgNewSeed $ seedFromInteger 10

givenPrivateKey = snd $ fst $ withDRG drg (RSA.generate 256 0x10001)

spec :: Spec
spec = do
  describe "Network.Yassh.HostKey.SshRsa.new" $ do
    context "given a configuration with private key" $ do
      describe "returns a server handler" $ do
        let serverHandler = new givenConfiguration
        it "has the correct name" $ do
          name serverHandler `shouldBe` "ssh-rsa"
        it "is signature capable" $ do
          serverHandler `shouldSatisfy` (isJust . sign)
        describe "the encoded key" $ do
          it "has the proper format (RFC4253.6.6)" $ do
            encodedKey serverHandler 
              `shouldBe` 
              [ SshString "ssh-rsa"
              , SshMPint (RSA.public_e $ RSA.private_pub givenPrivateKey)
              , SshMPint (RSA.public_n $ RSA.private_pub givenPrivateKey)
              ]
        describe "sign" $ do
          it "it has the proper encoded format (RFC4253.6.6)" $ do
            (fromJust (sign serverHandler)) "test-to-sign" 
              `shouldBe`
              [ SshString "ssh-rsa"
              , SshString (fromRight undefined $ PKCS15.sign Nothing (Just SHA1) givenPrivateKey "test-to-sign")
              ]
        

