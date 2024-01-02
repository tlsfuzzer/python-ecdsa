#!/bin/bash
set -e

cosmic-ray init cosmic-ray.toml session.sqlite
cosmic-ray baseline --session-file session.baseline.sqlite cosmic-ray.toml
cr-report --show-output session.baseline.sqlite
# some mutations cause huge memory use, so put it in a cgroup
# systemd-run --user --scope -p MemoryMax=2G -p MemoryHigh=2G cosmic-ray exec cosmic-ray.toml session.sqlite
cosmic-ray exec cosmic-ray.toml session.sqlite
cr-report session.sqlite
cr-html session.sqlite > session.html
cr-rate --estimate --fail-over 29 --confidence 99.9 session.sqlite
