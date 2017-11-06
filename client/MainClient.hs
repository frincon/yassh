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

import Control.Monad.IO.Class (liftIO)
import Development.Placeholders
import Network.Yassh (SshClient, runSshClient)
import System.Environment (getArgs)
import System.IO (BufferMode(NoBuffering), hSetBuffering, stdout)

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  args <- getArgs
  run args
  where
    run :: [String] -> IO ()
    run [] = putStrLn "worng arguments, at least 1"
    run (hostName:xs) = runSshClient hostName $ liftIO $ putStrLn "Connection established"
