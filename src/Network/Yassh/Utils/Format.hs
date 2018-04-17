-- Copyright 2018 Fernando Rincon Martin
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
-- limitations under the License.{-# LANGUAGE OverloadedStrings #-}
module Network.Yassh.Utils.Format
  ( decodePemDerRsaPrivateKey
  , encodePemDerRsaPrivateKey
  ) where

import Control.Arrow (left)
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.BinaryEncoding (DER(..))
import Data.ASN1.Encoding (decodeASN1', encodeASN1')
import Data.ASN1.Types
       (ASN1(..), ASN1ConstructionType(..), ASN1Object(..))
import Data.Bits (shiftR)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.PEM (PEM(..), pemContent, pemParseBS, pemWriteBS)

instance ASN1Object RSA.PrivateKey where
  toASN1 privKey xs =
    Start Sequence :
    IntVal 0 :
    IntVal (RSA.public_n $ RSA.private_pub privKey) :
    IntVal (RSA.public_e $ RSA.private_pub privKey) :
    IntVal (RSA.private_d privKey) :
    IntVal (RSA.private_p privKey) :
    IntVal (RSA.private_q privKey) :
    IntVal (RSA.private_dP privKey) : IntVal (RSA.private_dQ privKey) : IntVal (RSA.private_qinv privKey) : End Sequence : xs
  fromASN1 (Start Sequence:IntVal 0:IntVal n:IntVal e:IntVal d:IntVal p:IntVal q:IntVal dP:IntVal dQ:IntVal qinv:End Sequence:xs) =
    Right
      ( RSA.PrivateKey
        { RSA.private_pub = RSA.PublicKey {RSA.public_size = sizeInBytes n, RSA.public_n = n, RSA.public_e = e}
        , RSA.private_d = d
        , RSA.private_p = p
        , RSA.private_q = q
        , RSA.private_dP = dP
        , RSA.private_dQ = dQ
        , RSA.private_qinv = qinv
        }
      , xs)
  fromASN1 _ = Left "fromASN1: RSA.PrivateKey: unexpected format"

rsaPrivateKeyLabel = "RSA PRIVATE KEY"

decodePemDerRsaPrivateKey :: ByteString -> Either String RSA.PrivateKey
decodePemDerRsaPrivateKey input = do
  pem <- pemParseBS input
  asAsn1 <- left show $ decodeASN1' DER (pemContent $ head pem)
  fst <$> fromASN1 asAsn1

encodePemDerRsaPrivateKey :: RSA.PrivateKey -> ByteString
encodePemDerRsaPrivateKey privKey = pemWriteBS $ PEM rsaPrivateKeyLabel [] $ encodeASN1' DER $ toASN1 privKey []

sizeInBytes :: Integer -> Int
sizeInBytes i
  | i < 0 = error "Only for positives"
  | i == 0 = 0
  | i > 0 = 1 + sizeInBytes (i `shiftR` 8)
