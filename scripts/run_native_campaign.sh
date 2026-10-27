#!/usr/bin/env bash
set -u
cd /mnt/c/Users/Madhuri/Desktop/project/cn-project-lantern-main/cn-project-lantern-main
exec >> /mnt/c/Users/Madhuri/Desktop/project/cn-project-lantern-main/cn-project-lantern-main/results/campaigns/native-extended-20-v6/campaign.log 2>&1
export PATH="/mnt/c/Program Files/Docker/Docker/resources/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LANTERN_DOCKER=docker.exe
export LANTERN_NATIVE=1
export LANTERN_RYU_MANAGER=/opt/python3.8/bin/ryu-manager
export LANTERN_CONTROLLER_IP=127.0.0.1
export LANTERN_CONTROLLER_PORT=16653

CAMPAIGN=results/campaigns/native-extended-20-v6
python3 -m experiments.campaign calibrate --campaign "$CAMPAIGN" --topology-size 20
python3 -m experiments.campaign extended --campaign "$CAMPAIGN"
