#!/usr/bin/env python3
"""Test the acme_account_rollover script with real ACME server"""
import unittest
import os
import configparser
import acme_dns_tiny
from tests.config_factory import generate_acme_account_rollover_config
from tools.acme_account_deactivate import account_deactivate
import tools.acme_account_rollover

ACMEDIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2",
                          "https://acme-staging-v02.api.letsencrypt.org/directory")

class TestACMEAccountRollover(unittest.TestCase):
    "Tests for acme_account_rollover"

    @classmethod
    def setUpClass(cls):
        cls.configs = generate_acme_account_rollover_config()
        acme_dns_tiny.main([cls.configs['config']])
        super(TestACMEAccountRollover, cls).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    @classmethod
    def tearDownClass(cls):
        # deactivate account key registration at end of tests
        # (we assume the key has been roll oved)
        account_deactivate(cls.configs["newaccountkey"], ACMEDIRECTORY)
        # Remove temporary files
        parser = configparser.ConfigParser()
        parser.read(cls.configs['config'])
        try:
            os.remove(parser["acmednstiny"]["AccountKeyFile"])
            os.remove(parser["acmednstiny"]["CSRFile"])
            os.remove(cls.configs["newaccountkey"])
            os.remove(cls.configs['config'])
        except: # pylint: disable=bare-except
            pass
        super(TestACMEAccountRollover, cls).tearDownClass()

    def test_success_account_rollover(self):
        """ Test success account key rollover """
        with self.assertLogs(level='INFO') as accountrolloverlog:
            tools.acme_account_rollover.main(["--current", self.configs['oldaccountkey'],
                                              "--new", self.configs['newaccountkey'],
                                              "--acme-directory", ACMEDIRECTORY])
        self.assertIn("INFO:acme_account_rollover:Account keys rolled over !",
                      accountrolloverlog.output)

if __name__ == "__main__":
    unittest.main()
