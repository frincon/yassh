#!/bin/bash

find src/ test/ server/ client/ internal/ -type f -name "*.hs" -exec hindent {} \;

