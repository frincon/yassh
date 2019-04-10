{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Network.Yassh.HostKey.SshRsa
  ( Configuration(..)
  , ServerHandle(..)
  , new
  ) where

import Crypto.Hash (SHA1(..))
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import GHC.Stack
import Network.Yassh.HostKey
import Network.Yassh.Internal

import Development.Placeholders

data Configuration = Configuration
  { privateKey :: PrivateKey
  }

new :: Configuration -> ServerHandle
new Configuration {..} =
  ServerHandle
  { name = "ssh-rsa"
  , sign = Just $ privateSign privateKey
  , encrypt = Nothing -- TODO Is encryption capable?
  , encodedKey = [SshString "ssh-rsa", SshMPint pub_e, SshMPint pub_n]
  }
  where
    pub_e = public_e $ private_pub privateKey
    pub_n = public_n $ private_pub privateKey


-- TODO this either is litle bit ugly
privateSign :: HasCallStack => PrivateKey -> Sign
privateSign privateKey input =
    [ SshString "ssh-rsa"
    , SshString $ either (error . show) id $ Crypto.PubKey.RSA.PKCS15.sign Nothing (Just SHA1) privateKey input
    ]
