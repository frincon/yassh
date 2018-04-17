{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.Yassh.HostKey.SshRsa
  ( Configuration(..)
  , ServerHandle(..)
  , new
  )
where

import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Crypto.Hash (SHA1(..))
import Network.Yassh.HostKey
import Network.Yassh.Internal
import GHC.Stack

data Configuration = Configuration
  { privateKey :: PrivateKey
  }

new :: Configuration -> ServerHandle
new Configuration{..} = ServerHandle
  { name = "ssh-rsa"
  , sign = Just $ privateSign privateKey
  , encrypt = Nothing -- TODO It is encryption capable
  , encodedKey = sshEncode [SshString "ssh-rsa", SshMPint pub_e, SshMPint pub_n]
  }
  where
    pub_e = public_e $ private_pub privateKey
    pub_n = public_n $ private_pub privateKey

privateSign :: HasCallStack => PrivateKey -> Sign
privateSign privateKey input =
  sshEncode
    [ SshString "ssh-rsa"
    , SshString $ either (error . show) id $ Crypto.PubKey.RSA.PKCS15.sign Nothing (Just SHA1) privateKey input
    ]
