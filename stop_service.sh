#!/bin/sh
ps aux | grep googleapis_Service.py | awk '{print $2}' | xargs kill