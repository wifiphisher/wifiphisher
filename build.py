from hatchling.builders.hooks.plugin.interface import BuildHookInterface
import subprocess
import sys

class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        """Run pre-installation checks before build"""
        try:
            # Run the pre-installation checks
            subprocess.run([sys.executable, 'pre_install.py'], check=True)
        except subprocess.CalledProcessError as e:
            # If checks fail, abort the build
            sys.exit(1) 