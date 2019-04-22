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
module Network.Yassh.Internal.KeyExchangeSpec
( spec
)
where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as CBS
import Data.Either (isLeft, isRight)
import Data.List (nub, intersect)
import Development.Placeholders
import Test.QuickCheck
import Test.QuickCheck.Instances.ByteString
import qualified Data.List.NonEmpty as NE

import Network.Yassh.Test.Utils
import Network.Yassh.Internal
import Network.Yassh.Internal.KeyExchange

instance Arbitrary a => Arbitrary (BiDirectional a) where
  arbitrary = BiDirectional <$> arbitrary <*> arbitrary

instance Arbitrary NegotiationSet where
  arbitrary = 
    NegotiationSet <$> 
    arbitraryKex <*> arbitraryHostKey <*> arbitraryEncryption <*> arbitraryMac <*> arbitraryCompression <*> arbitrary
    where
      generateList :: BS.ByteString -> [BS.ByteString]
      generateList prefix = fmap (\a -> BS.append prefix $ CBS.pack $ show a) [1..5]
      generateNEList :: BS.ByteString -> Gen (NE.NonEmpty BS.ByteString)
      generateNEList prefix = do 
        list <- resize 5 $ listOf1 $ elements $ generateList prefix
        return $ NE.fromList $ nub list
      generateBidirectional prefix = do
        list1 <- generateNEList prefix
        list2 <- generateNEList prefix
        return $ BiDirectional list1 list2

      arbitraryKex = generateNEList "kex"
      arbitraryHostKey = generateNEList "key"
      arbitraryEncryption = generateBidirectional "enc"
      arbitraryMac = generateBidirectional "mac"
      arbitraryCompression = generateBidirectional "comp"

spec :: Spec
spec = do
  runAlgorithmNegotiationSpec
  resolveAlgorithmsSpec

resolveAlgorithmsSpec :: Spec
resolveAlgorithmsSpec = do
  describe "Network.Yassh.Internal.KeyExchangeSpec.resolveAlgorithmsSpec" $ do
    context "the kex and host keys are compatible" $ do
      it "if there is a common algorithm in all list should return success otherwise error" $ 
        property $
          \sets@(BiDirectional ctos stoc) -> 
            if existsAlgorithmsInCommon ctos stoc 
              then isRight $ resolveAlgorithms (\_ _ -> True) sets
              else isLeft $ resolveAlgorithms (\_ _ -> True) sets
    context "the kex and host keys are incompatible" $ do
      it "returns always error" $ property $
        \sets@(BiDirectional ctos stoc) -> 
          isLeft $ resolveAlgorithms (\_ _ -> False) sets
    context "special case when the first kex match" $ do
      it "fails when the first match but there is no key algorithm" $ do
        let neg1 = NegotiationSet 
              { kexAlgs = NE.fromList ["kex2", "kex1"]
              , serverHostKeyAlgs = NE.fromList ["serverHostKeyAlgs1", "serverHostKeyAlgs2"]
              , encryptionAlgs = BiDirectional (NE.fromList ["enc1", "enc2"]) (NE.fromList ["enc3", "enc4"])
              , macAlgs = BiDirectional (NE.fromList ["mac1", "mac2"]) (NE.fromList ["mac3", "mac4"])
              , compressionAlgs = BiDirectional (NE.fromList ["comp1", "comp2"]) (NE.fromList ["comp3", "comp4"])
              , languages = BiDirectional ["lang1", "lang2"] ["lang3", "lang4"]
              }
        let neg2 = NegotiationSet
              { kexAlgs = NE.fromList ["kex2", "kex1"]
              , serverHostKeyAlgs = NE.fromList ["serverHostKeyAlgs1", "serverHostKeyAlgs2"]
              , encryptionAlgs = BiDirectional (NE.fromList ["enc1", "enc2"]) (NE.fromList ["enc3", "enc4"])
              , macAlgs = BiDirectional (NE.fromList ["mac1", "mac2"]) (NE.fromList ["mac3", "mac4"])
              , compressionAlgs = BiDirectional (NE.fromList ["comp1", "comp2"]) (NE.fromList ["comp3", "comp4"])
              , languages = BiDirectional ["lang1", "lang2"] ["lang3", "lang4"]
              }
        resolveAlgorithms (\kex key -> kex == "kex1" && key == "serverHostKeyAlgs2") (BiDirectional neg1 neg2)
          `shouldSatisfy` isLeft

  where
    existsAlgorithmsInCommon ctos stoc = 
      let 
        NegotiationSet kex1 key1 enc1 mac1 comp1 _ = ctos
        NegotiationSet kex2 key2 enc2 mac2 comp2 _ = stoc
        BiDirectional enc1ctos enc1stoc = enc1
        BiDirectional enc2ctos enc2stoc = enc2
        BiDirectional mac1ctos mac1stoc = mac1
        BiDirectional mac2ctos mac2stoc = mac2
        BiDirectional comp1ctos comp1stoc = comp1
        BiDirectional comp2ctos comp2stoc = comp2
      in
        not 
          (  null (intersect (NE.toList kex1) (NE.toList kex2))
          || null (intersect (NE.toList key1) (NE.toList key2))
          || null (intersect (NE.toList enc1ctos) (NE.toList enc2ctos))
          || null (intersect (NE.toList enc1stoc) (NE.toList enc2stoc))
          || null (intersect (NE.toList mac1ctos) (NE.toList mac2ctos))
          || null (intersect (NE.toList mac1stoc) (NE.toList mac2stoc))
          || null (intersect (NE.toList comp1ctos) (NE.toList comp2ctos))
          || null (intersect (NE.toList comp1stoc) (NE.toList comp2stoc))
          )

runAlgorithmNegotiationSpec = do
  describe "Network.Yassh.Internal.KeyExchangeSpec.runAlgorithmNegotiation" $ do
    it "expect a SSH_MSG_KEXINIT" $ do
      (recvMock, recvCalls) <- mockP1' (\_ -> return $ mkSshMsgKexinit True givenNegotiationSet)
      (sendMock, _) <- mockP1
      runAlgorithmNegotiation recvMock sendMock (\_ -> Right undefined) givenNegotiationSet
      recvCalls `shouldReturn` [[c_SSH_MSG_KEXINIT]]
    it "should sent a SSH_MSG_KEXINIT" $ do
      (recvMock, _) <- mockP1' (\_ -> return $ mkSshMsgKexinit True givenNegotiationSet)
      (sendMock, sendCalls) <- mockP1
      runAlgorithmNegotiation recvMock sendMock (\_ -> Right undefined) givenNegotiationSet
      calls <- sendCalls
      length calls `shouldBe` 1
      let (SshPacket code _) = last calls
      code `shouldBe` c_SSH_MSG_KEXINIT
    context "The packet SSH_MSG_KEXINIT sent" $ do
      it "should contains the proper negotation set" $ do
        (recvMock, _) <- mockP1' (\_ -> return $ mkSshMsgKexinit True givenNegotiationSet)
        (sendMock, sendCalls) <- mockP1
        runAlgorithmNegotiation recvMock sendMock (\_ -> Right undefined) givenNegotiationSet
        (SshPacket _ fields) <- last <$> sendCalls
        fields!!1 `shouldBe` (SshNameList $ NE.toList $ kexAlgs givenNegotiationSet)
        fields!!2 `shouldBe` (SshNameList $ NE.toList $ serverHostKeyAlgs givenNegotiationSet)
      it "should contains a random cookie" $ do
        (recvMock, _) <- mockP1' (\_ -> return $ mkSshMsgKexinit True givenNegotiationSet)
        (sendMock, sendCalls) <- mockP1
        runAlgorithmNegotiation recvMock sendMock (\_ -> Right undefined) givenNegotiationSet
        runAlgorithmNegotiation recvMock sendMock (\_ -> Right undefined) givenNegotiationSet
        calls <- sendCalls
        length calls `shouldBe` 2
        let (SshPacket _ fields1) = calls!!0
        let (SshPacket _ fields2) = calls!!1
        let (SshByteArray length1 cookie1) = fields1!!0
        let (SshByteArray length2 cookie2) = fields2!!0
        length1 `shouldBe` 16
        length2 `shouldBe` 16
        cookie1 `shouldNotBe` cookie2
        BS.length cookie1 `shouldBe` 16
        BS.length cookie2 `shouldBe` 16
    it "should discard following packet when a guest is wrong" $ do
      (recvMock, recvCalls) <- mockP1' (\_ -> return $ mkSshMsgKexinit True givenNegotiationSetGuestWrong)
      (sendMock, sendCalls) <- mockP1
      runAlgorithmNegotiation recvMock sendMock (\_ -> Right undefined) givenNegotiationSet
      calls <- recvCalls
      length calls `shouldBe` 2
      calls!!0 `shouldBe` [30..49]
    it "should not discard any packet when a guest is wrong but not following packet has sent" $ do
      (recvMock, recvCalls) <- mockP1' (\_ -> return $ mkSshMsgKexinit False givenNegotiationSetGuestWrong)
      (sendMock, sendCalls) <- mockP1
      runAlgorithmNegotiation recvMock sendMock (\_ -> Right undefined) givenNegotiationSet
      calls <- recvCalls
      length calls `shouldBe` 1
    it "should fail when the result of negotiation is left" $ do
      (recvMock, recvCalls) <- mockP1' (\_ -> return $ mkSshMsgKexinit False givenNegotiationSetGuestWrong)
      (sendMock, sendCalls) <- mockP1
      (runAlgorithmNegotiation recvMock sendMock (\_ -> Left "the-error") givenNegotiationSet)
        `shouldThrow` anyException -- TODO better exception?
  
givenNegotiationSet :: NegotiationSet
givenNegotiationSet = 
  NegotiationSet 
    { kexAlgs = NE.fromList ["kex1", "kex2"]
    , serverHostKeyAlgs = NE.fromList ["serverHostKeyAlgs1", "serverHostKeyAlgs1"]
    , encryptionAlgs = BiDirectional (NE.fromList ["enc1", "enc2"]) (NE.fromList ["enc3", "enc4"])
    , macAlgs = BiDirectional (NE.fromList ["mac1", "mac2"]) (NE.fromList ["mac3", "mac4"])
    , compressionAlgs = BiDirectional (NE.fromList ["comp1", "comp2"]) (NE.fromList ["comp3", "comp4"])
    , languages = BiDirectional ["lang1", "lang2"] ["lang3", "lang4"]
    }

givenNegotiationSetGuestWrong :: NegotiationSet
givenNegotiationSetGuestWrong = 
  NegotiationSet 
    { kexAlgs = NE.fromList ["kex2", "kex1"]
    , serverHostKeyAlgs = NE.fromList ["serverHostKeyAlgs1", "serverHostKeyAlgs1"]
    , encryptionAlgs = BiDirectional (NE.fromList ["enc1", "enc2"]) (NE.fromList ["enc3", "enc4"])
    , macAlgs = BiDirectional (NE.fromList ["mac1", "mac2"]) (NE.fromList ["mac3", "mac4"])
    , compressionAlgs = BiDirectional (NE.fromList ["comp1", "comp2"]) (NE.fromList ["comp3", "comp4"])
    , languages = BiDirectional ["lang1", "lang2"] ["lang3", "lang4"]
    }  

mkSshMsgKexinit :: Bool -> NegotiationSet -> SshRawPacket
mkSshMsgKexinit follow negotiationSet = 
  SshRawPacket c_SSH_MSG_KEXINIT $ sshEncode
  [ SshByteArray 16 $ BS.replicate 16 55
  , SshNameList $ NE.toList $ kexAlgs negotiationSet
  , SshNameList $ NE.toList $ serverHostKeyAlgs negotiationSet
  , SshNameList $ NE.toList $ clientToServer $ encryptionAlgs negotiationSet
  , SshNameList $ NE.toList $ serverToClient $ encryptionAlgs negotiationSet
  , SshNameList $ NE.toList $ clientToServer $ macAlgs negotiationSet
  , SshNameList $ NE.toList $ serverToClient $ macAlgs negotiationSet
  , SshNameList $ NE.toList $ clientToServer $ compressionAlgs negotiationSet
  , SshNameList $ NE.toList $ serverToClient $ compressionAlgs negotiationSet
  , SshNameList $ clientToServer $ languages negotiationSet
  , SshNameList $ serverToClient $ languages negotiationSet
  , SshBoolean follow
  , SshUInt32 0 -- Future use
  ]


