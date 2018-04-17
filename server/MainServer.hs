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

import qualified Crypto.PubKey.RSA as RSA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Network.Yassh.IOStreams
import Network.Yassh.Utils.Format
       (decodePemDerRsaPrivateKey, encodePemDerRsaPrivateKey)
import System.Directory
       (XdgDirectory(XdgConfig), createDirectoryIfMissing, doesFileExist,
        getXdgDirectory)
import System.FilePath ((</>), takeDirectory)
import System.IO (BufferMode(NoBuffering), hSetBuffering, stdout)
import System.IO.Streams (InputStream, OutputStream)
import qualified System.IO.Streams as Streams

programName = "yassh-server"

rsaFileNamePriv = "host_rsa"

-- rsaFileNamePub = "host_rsa.pub"
main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  configDirectory <- getXdgDirectory XdgConfig programName
  hostKey <- readOrCreateKey $ configDirectory </> rsaFileNamePriv
  runSshServer 2022 hostKey dummyShell

readOrCreateKey :: FilePath -> IO RSA.PrivateKey
readOrCreateKey rsaPrivFile = do
  fileExists <- doesFileExist rsaPrivFile
  if fileExists
    then readRsaPrivFile rsaPrivFile
    else do
      putStrLn $ "File " ++ rsaPrivFile ++ " does not exists. Generating a new host key..."
      (_, privateKey) <- RSA.generate 256 65537
      print privateKey
      saveRsaPrivFile privateKey rsaPrivFile
      return privateKey

readRsaPrivFile :: FilePath -> IO RSA.PrivateKey
readRsaPrivFile rsaPrivFile = do
  content <- BS.readFile rsaPrivFile
  case decodePemDerRsaPrivateKey content of
    Left err -> error $ "Reading file " ++ rsaPrivFile ++ " error: " ++ err
    Right privKey -> do
      print privKey
      return privKey

saveRsaPrivFile :: RSA.PrivateKey -> FilePath -> IO ()
saveRsaPrivFile rsaPrivKey rsaPrivFile = do
  createDirectoryIfMissing False (takeDirectory rsaPrivFile)
  BS.writeFile rsaPrivFile $ encodePemDerRsaPrivateKey rsaPrivKey

dummyShell :: (InputStream ByteString, OutputStream ByteString) -> IO ()
dummyShell (is, os) = do
  isLines <- Streams.lines is -- TODO This is not safe as can blow up the memory if there is no end of line
  loop (isLines, os)
  where
    loop (is, os) = do
      maybeLine <- Streams.read is
      case maybeLine of
        Just line -> do
          Streams.write (Just $ BS.concat ["I can't understand '", line, "'\n"]) os
          loop (is, os)
        Nothing -> Streams.write Nothing os
