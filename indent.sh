#!/bin/bash

find src/ test/ server/ client/ -type f -name "*.hs" -exec hindent {} \;

