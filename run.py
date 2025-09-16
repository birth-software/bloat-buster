#!/usr/bin/env python3
import os
import subprocess
import sys

result = subprocess.run(["build/bb"])
return_code = result.returncode
sys.exit(return_code)
