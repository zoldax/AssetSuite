#!/usr/bin/env python3

"""
AssetSuite.py

A utility script to manage IBM QRadar assets: check the connection and the
API capabilities of the target QRadar (export, import and reports to come).

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import sys

from assetsuite.cli import main

if __name__ == "__main__":
    sys.exit(main())
