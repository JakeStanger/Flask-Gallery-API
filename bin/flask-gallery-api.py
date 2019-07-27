#!/usr/bin/env python3
import flask_gallery_api
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config')
args = parser.parse_args()

with open(args.config, 'r') as f:
    config = f.read()

flask_gallery_api.run(json.loads(config))
