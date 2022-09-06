#!/bin/bash

# sync current directory to server vm
echo "syncing to server vm..."
rsync -a . 192.168.122.223:/home/sdic/shenango
