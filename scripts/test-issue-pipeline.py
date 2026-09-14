#!/usr/bin/env python3
"""Run the controller's offline safety and recovery tests."""
import pathlib
import sys
import unittest
sys.dont_write_bytecode = True

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(pathlib.Path(__file__).with_name("issue_pipeline_tests")))
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
