#!/usr/bin/env python3
import os
import subprocess
import sys

result = subprocess.run(["ninja", "--quiet"], cwd="build")
return_code = result.returncode
sys.exit(return_code)
