module Network.Yassh.Test.Utils
( mockP1
, mockP1'
)
where

import Control.Concurrent.STM (atomically)
import Control.Concurrent.STM.TVar (newTVarIO, modifyTVar, readTVarIO)

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
  