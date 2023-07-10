#!/usr/bin/env bash

rm -r dist
poetry build
python3 -m pip install $(ls dist/*.tar.gz)
