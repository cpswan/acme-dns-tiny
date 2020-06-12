"""Tests for acme_dns_tiny script to be run with real ACME server"""
import unittest
import sys
import os
import subprocess
import configparser
from io import StringIO
import dns.version
import acme_dns_tiny
from tests.config_factory import generate_acme_dns_tiny_config
from tools.acme_account_deactivate import account_deactivate

ACME_DIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2",
                           "https://acme-staging-v02.api.letsencrypt.org/directory")


def _openssl(command, options, communicate=None):
    """Helper function to run openssl command."""
    openssl = subprocess.Popen(["openssl", command] + options,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out.decode("utf8")


class TestACMEDNSTiny(unittest.TestCase):
    """Tests for acme_dns_tiny.get_crt()."""

    @classmethod
    def setUpClass(cls):
        print("Init acme_dns_tiny with python modules:")
        print("  - python: {0}".format(sys.version))
        print("  - dns python: {0}".format(dns.version.version))
        cls.configs = generate_acme_dns_tiny_config()
        sys.stdout.flush()
        super(TestACMEDNSTiny, cls).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    # pylint: disable=bare-except
    @classmethod
    def tearDownClass(cls):
        # close temp files correctly
        for conffile in cls.configs:
            # for each configuration file, deactivate the account and remove linked temporary files
            if conffile != "cname_csr":
                parser = configparser.ConfigParser()
                parser.read(cls.configs[conffile])
                try:
                    account_deactivate(parser["acmednstiny"]["AccountKeyFile"], ACME_DIRECTORY)
                except:
                    pass
                try:
                    os.remove(parser["acmednstiny"]["AccountKeyFile"])
                except:
                    pass
                try:
                    os.remove(parser["acmednstiny"]["CSRFile"])
                except:
                    pass
            try:
                os.remove(cls.configs[conffile])
            except:
                pass
        super(TestACMEDNSTiny, cls).tearDownClass()

    # helper function to valid success by making assertion on returned certificate chain
    def _assert_certificate_chain(self, cert_chain):
        # Output have to contains two certificates
        certlist = cert_chain.split("-----BEGIN CERTIFICATE-----")
        self.assertEqual(3, len(certlist))
        self.assertEqual('', certlist[0])
        self.assertIn("-----END CERTIFICATE-----{0}".format(os.linesep), certlist[1])
        self.assertIn("-----END CERTIFICATE-----{0}".format(os.linesep), certlist[2])
        # Use openssl to check validity of chain and simple test of readability
        readablecertchain = _openssl("x509", ["-text", "-noout"],
                                     cert_chain.encode("utf8"))
        self.assertIn("Issuer", readablecertchain)

    def test_success_cn(self):
        """Successfully issue a certificate via common name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['good_cname'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_cn_without_contacts(self):
        """Successfully issue a certificate via CN, but without Contacts field."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['good_cname_without_contacts'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_cn_with_csr_option(self):
        """Successfully issue a certificate using CSR option outside from the config file."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main(["--csr", self.configs['cname_csr'],
                            self.configs['good_cname_without_csr'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_wild_cn(self):
        """Successfully issue a certificate via a wildcard common name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['wild_cname'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_dnshost_ip(self):
        """When DNS Host is an IP, DNS resolution have to fail without error."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        with self.assertLogs(level='INFO') as adnslog:
            acme_dns_tiny.main([self.configs['dns_host_ip'],
                                "--verbose"])
        self.assertIn(("INFO:acme_dns_tiny:A and/or AAAA DNS resources not found for configured "
                       "dns host: we will use either resource found if one exists or directly the "
                       "DNS Host configuration."), adnslog.output)
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_san(self):
        """Successfully issue a certificate via subject alt name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['good_san'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_wildsan(self):
        """Successfully issue a certificate via wildcard in subject alt name."""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['wild_san']])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self._assert_certificate_chain(certchain)

    def test_success_cli(self):
        """Successfully issue a certificate via command line interface."""
        certout, _ = subprocess.Popen([
            "python3", "acme_dns_tiny.py", self.configs['good_cname'], "--verbose"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

        certchain = certout.decode("utf8")

        self._assert_certificate_chain(certchain)

    def test_success_cli_with_csr_option(self):
        """Successfully issue a certificate via command line interface using CSR option."""
        certout, _ = subprocess.Popen([
            "python3", "acme_dns_tiny.py", "--csr", self.configs['cname_csr'],
            self.configs['good_cname_without_csr'], "--verbose"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

        certchain = certout.decode("utf8")

        self._assert_certificate_chain(certchain)

    def test_weak_key(self):
        """Let's Encrypt rejects weak keys."""
        self.assertRaisesRegex(ValueError,
                               "key too small",
                               acme_dns_tiny.main, [self.configs['weak_key'], "--verbose"])

    def test_account_key_domain(self):
        """Can't use the account key for the CSR."""
        self.assertRaisesRegex(ValueError,
                               "certificate public key must be different than account key",
                               acme_dns_tiny.main, [self.configs['account_as_domain'],
                                                    "--verbose"])

    def test_failure_dns_update_tsigkeyname(self):
        """Fail to update DNS records by invalid TSIG Key name."""
        self.assertRaisesRegex(ValueError,
                               "Error updating DNS",
                               acme_dns_tiny.main, [self.configs['invalid_tsig_name'],
                                                    "--verbose"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
