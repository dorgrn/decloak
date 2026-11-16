#!/bin/sh
payload=$(echo aWQ= | base64 --decode)
eval "$payload"
