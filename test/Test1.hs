module Test1
  ()
where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Free

test :: IO ()
test = runInterr [test1, test2]

test1 :: (MonadInterr m, MonadIO m) => m String
test1 = do
  liftIO $ putStrLn "IO1 from test1"
  interrOne "1 from test1"
  liftIO $ putStrLn "IO2 from test1"
  interrOne "2 from test1"
  liftIO $ putStrLn "IO3 from test1"
  interrTwo "3 from test1"
  liftIO $ putStrLn "IO4 from test1"
  interrTwo "4 from test1"
  liftIO $ putStrLn "IO5 from test1"
  return "Test1"

test2 :: (MonadInterr m, MonadIO m) => m String
test2 = do
  liftIO $ putStrLn "IO1 from test2"
  interrOne "1 from test2"
  liftIO $ putStrLn "IO2 from test2"
  interrOne "2 from test2"
  liftIO $ putStrLn "IO3 from test2"
  interrTwo "3 from test2"
  liftIO $ putStrLn "IO4 from test2"
  interrTwo "4 from test2"
  liftIO $ putStrLn "IO5 from test2"
  return "Test2"

data SshF next = ReceivePacket [Int] (String -> next) | SendPacket String next

instance Functor SshF where
     fmap f (ReceivePacket ints k) = ReceivePacket ints (f . k)
     fmap f (SendPacket str x) = SendPacket str (f x)

type Ssh a = Free SshF a

receivePacket :: [Int] -> Ssh String
receivePacket ints = liftF $ ReceivePacket ints id

sendPacket :: String -> Ssh ()
sendPacket str = liftF $ SendPacket str ()
