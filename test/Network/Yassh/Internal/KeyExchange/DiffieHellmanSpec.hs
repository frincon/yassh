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
module Network.Yassh.Internal.KeyExchange.DiffieHellmanSpec
(
  spec
)
where

import Crypto.Hash
import Crypto.PubKey.DH
import Crypto.Random
import Crypto.Number.Serialize


import Development.Placeholders
import System.Timeout (timeout)
import Data.Word (Word8)
import Data.Maybe (fromJust)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Control.Concurrent.STM (atomically)
import Control.Concurrent.STM.TVar (newTVarIO, modifyTVar, readTVarIO)
import Test.Hspec

import Network.Yassh.Internal.KeyExchange.DiffieHellman
import Network.Yassh.KeyExchange
import qualified Network.Yassh.HostKey as HostKey
import Network.Yassh.Internal

spec :: Spec
spec = do
  describe "Network.Yassh.Internal.KeyExchange.DiffieHellman.diffieHellmanGroup14Sha1" $ do
    describe "returns a serverHandle" $ do
      let serverHandle = diffieHellmanGroup14Sha1
      it "returns correct name" $ do
        name serverHandle `shouldBe` "diffie-hellman-group14-sha1"
      it "requres signature capable host key" $ do
        requiresHostKeySignatureCapable serverHandle `shouldBe` True
      it "does not require encryption capable host key" $ do
        requiresHostKeyEncryptionCapable serverHandle `shouldBe` False
      context "given a kex server context" $ do
        describe "runKex" $ do
          it "should accept a SSH_MSG_KEXDH_INIT from the client" $ do
            (mockedReceive, callsReceive) <- mockP1
            (mockedSend, callsSend) <- mockP1
            runKex serverHandle givenKexServerContext mockedReceive mockedSend
            callsReceive `shouldReturn` [[c_SSH_MSG_KEXDH_INIT]]
          it "should send a SSH_MSG_KEXDH_REPLY after receiving a SSH_MSG_KEXDH_INIT" $ do
            (mockedReceive, callsReceive) <- mockP1
            (mockedSend, callsSend) <- mockP1
            runKex serverHandle givenKexServerContext mockedReceive mockedSend
            calls <- callsSend
            length calls `shouldBe` 1
            let (SshPacket code _) = last calls
            code `shouldBe` c_SSH_MSG_KEXDH_REPLY
          it "the SSH_MSG_KEXDH_REPLY should be well formed (RFC4253.8)" $ do
            (mockedReceive, callsReceive) <- mockP1
            (mockedSend, callsSend) <- mockP1
            runKex serverHandle givenKexServerContext mockedReceive mockedSend
            calls <- callsSend
            let (SshPacket _ sshData) = last calls
            length sshData `shouldBe` 3
          it "the SSH_MSG_KEXDH_REPLY should contains the encoded key of the choosen hostkey alg" $ do
            (mockedReceive, callsReceive) <- mockP1
            (mockedSend, callsSend) <- mockP1
            runKex serverHandle givenKexServerContext mockedReceive mockedSend
            calls <- callsSend
            let (SshPacket _ sshData) = last calls
            sshData!!0 `shouldBe` (SshString $ sshEncode givenEncodedKey)
          it "the SSH_MSG_KEXDH_REPLY should have a publicNumber" $ do
            (mockedReceive, callsReceive) <- mockP1
            (mockedSend, callsSend) <- mockP1
            runKex serverHandle givenKexServerContext mockedReceive mockedSend
            calls <- callsSend
            let (SshPacket _ sshData) = last calls
            sshData!!1 `shouldSatisfy` isMPint
          it "the SSH_MSG_KEXDH_REPLY should have the correct signature" $ do
            let drg = drgNewSeed $ seedFromInteger 10
            let privateNumber = fst $ withDRG drg (generatePrivate group14params)
            let publicNumber@(PublicNumber publicNumberAsInteger) = calculatePublic group14params privateNumber
            (mockedReceive, callsReceive) <- mockP1' (\_ -> return $ SshRawPacket c_SSH_MSG_KEXDH_INIT $ sshEncode [SshMPint publicNumberAsInteger])
            (mockedSend, callsSend) <- mockP1
            runKex serverHandle givenKexServerContext mockedReceive mockedSend
            calls <- callsSend
            let (SshPacket _ [SshString _, SshMPint otherPartyPublicNumberAsInteger, SshString receivedSignat]) = last calls
            let sharedKey = getShared group14params privateNumber (PublicNumber otherPartyPublicNumberAsInteger)
            let exchangePacket =
                    [ SshString $ clientData $ kexContextIdentificationString givenKexServerContext
                    , SshString $ serverData $ kexContextIdentificationString givenKexServerContext
                    , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ clientData $ kexContextMsgInit givenKexServerContext)
                    , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ serverData $ kexContextMsgInit givenKexServerContext)
                    , SshString $ sshEncode $ HostKey.encodedKey $ kexContextHostKeyHandle givenKexServerContext
                    , SshMPint $ publicNumberAsInteger
                    , SshMPint $ otherPartyPublicNumberAsInteger
                    , SshMPint $ os2ip sharedKey
                    ]
            let exchangeString = sshEncode exchangePacket
            let exchangeHash = (convert $ (hash exchangeString :: Digest SHA1)) :: ByteString
            let signat = sshEncode $ fromJust (HostKey.sign (kexContextHostKeyHandle givenKexServerContext)) exchangeHash
            receivedSignat `shouldBe` signat
          it "should return the correct key and signature" $ do
            let drg = drgNewSeed $ seedFromInteger 10
            let privateNumber = fst $ withDRG drg (generatePrivate group14params)
            let publicNumber@(PublicNumber publicNumberAsInteger) = calculatePublic group14params privateNumber
            (mockedReceive, callsReceive) <- mockP1' (\_ -> return $ SshRawPacket c_SSH_MSG_KEXDH_INIT $ sshEncode [SshMPint publicNumberAsInteger])
            (mockedSend, callsSend) <- mockP1
            (key, h) <- runKex serverHandle givenKexServerContext mockedReceive mockedSend
            calls <- callsSend
            let (SshPacket _ [SshString _, SshMPint otherPartyPublicNumberAsInteger, SshString receivedSignat]) = last calls
            let sharedKey = getShared group14params privateNumber (PublicNumber otherPartyPublicNumberAsInteger)
            let exchangePacket =
                    [ SshString $ clientData $ kexContextIdentificationString givenKexServerContext
                    , SshString $ serverData $ kexContextIdentificationString givenKexServerContext
                    , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ clientData $ kexContextMsgInit givenKexServerContext)
                    , SshString $ BS.append (BS.singleton c_SSH_MSG_KEXINIT) (sshRawPacketPayload $ serverData $ kexContextMsgInit givenKexServerContext)
                    , SshString $ sshEncode $ HostKey.encodedKey $ kexContextHostKeyHandle givenKexServerContext
                    , SshMPint $ publicNumberAsInteger
                    , SshMPint $ otherPartyPublicNumberAsInteger
                    , SshMPint $ os2ip sharedKey
                    ]
            let exchangeString = sshEncode exchangePacket
            let exchangeHash = (convert $ (hash exchangeString :: Digest SHA1)) :: ByteString
            let signat = sshEncode $ fromJust (HostKey.sign (kexContextHostKeyHandle givenKexServerContext)) exchangeHash
            key `shouldBe` (convert sharedKey)
            h `shouldBe` exchangeHash


isMPint :: SshData -> Bool
isMPint (SshMPint _) = True
isMPint _ = False

givenEncodedKey :: [SshData]
givenEncodedKey = [SshString "testing"]

givenKexServerContext :: KexServerContext
givenKexServerContext = 
  KexContext
    { kexContextIdentificationString = SshClientServer "client" "server"
    , kexContextMsgInit = SshClientServer (SshRawPacket 20 "client-test") (SshRawPacket 20 "server-test")
    , kexContextHostKeyHandle = HostKey.ServerHandle 
      { HostKey.name = undefined
      , HostKey.sign = Just (\i -> [SshString i])
      , HostKey.encrypt = undefined
      , HostKey.encodedKey = givenEncodedKey
      }
    }

mockP1 :: IO (p -> IO r, IO [p])
mockP1 = do
  calls <- newTVarIO []
  return 
    (\i -> do
      atomically $ modifyTVar calls (\xs -> (i:xs))
      return undefined
    , readTVarIO calls
    )

mockP1' :: (p -> IO r) -> IO (p -> IO r, IO [p])
mockP1' func = do
  calls <- newTVarIO []
  return 
    (\i -> do
      atomically $ modifyTVar calls (\xs -> (i:xs))
      func i
    , readTVarIO calls
    )
