import unittest, sys, os, subprocess, time, configparser
from io import StringIO
import dns.version
import acme_dns_tiny
from tests.config_factory import generate_acme_dns_tiny_config
from tools.acme_account_deactivate import account_deactivate

ACMEDirectory = os.getenv("GITLABCI_ACMEDIRECTORY_V2", "https://acme-staging-v02.api.letsencrypt.org/directory")

class TestACMEDNSTiny(unittest.TestCase):
    "Tests for acme_dns_tiny.get_crt()"

    @classmethod
    def setUpClass(self):
        print("Init acme_dns_tiny with python modules:")
        print("  - python: {0}".format(sys.version))
        print("  - dns python: {0}".format(dns.version.version))
        self.configs = generate_acme_dns_tiny_config()
        sys.stdout.flush()
        super(TestACMEDNSTiny, self).setUpClass()

    # To clean ACME staging server and close correctly temporary files
    @classmethod
    def tearDownClass(self):
        # close temp files correctly
        for conffile in self.configs:
            parser = configparser.ConfigParser()
            parser.read(conffile)
            try:
                os.remove(parser["acmednstiny"]["AccountKeyFile"])
                os.remove(parser["acmednstiny"]["CSRFile"])
                # for each configuraiton, deactivate the account key
                if conffile != "cnameCSR":
                    account_deactivate(parser["acmednstiny"]["AccountKeyFile"], ACMEDirectory)
                os.remove(conffile)
            except:
                pass
        super(TestACMEDNSTiny, self).tearDownClass()

    # helper function to run openssl command
    def openssl(self, command, options, communicate=None):
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out.decode("utf8")

    # helper function to valid success by making assertion on returned certificate chain
    def assertCertificateChain(self, certificateChain):
        # Output have to contains two certiicates
        certlist = certificateChain.split("-----BEGIN CERTIFICATE-----")
        self.assertEqual(3, len(certlist))
        self.assertEqual('', certlist[0])
        self.assertIn("-----END CERTIFICATE-----{0}".format(os.linesep), certlist[1])
        self.assertIn("-----END CERTIFICATE-----{0}".format(os.linesep), certlist[2])
        # Use openssl to check validity of chain and simple test of readability
        readablecertchain = self.openssl("x509", ["-text", "-noout"], certificateChain.encode("utf8"))
        self.assertIn("Issuer", readablecertchain)

    def test_success_cn(self):
        """ Successfully issue a certificate via common name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        acme_dns_tiny.main([self.configs['goodCName'], "--verbose"])
        certchain = sys.stdout.getvalue()
        
        sys.stdout.close()
        sys.stdout = old_stdout
        
        self.assertCertificateChain(certchain)

    def test_success_cn_without_contacts(self):
        """ Successfully issue a certificate via CN, but without Contacts field """
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['goodCNameWithoutContacts'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self.assertCertificateChain(certchain)

    def test_success_cn_with_csr_option(self):
        """ Successfully issue a certificate using CSR option outside from the config file"""
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main(["--csr", self.configs['cnameCSR'], self.configs['goodCNameWithoutCSR'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self.assertCertificateChain(certchain)

    def test_success_wild_cn(self):
        """ Successfully issue a certificate via a wildcard common name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['wildCName'], "--verbose"])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self.assertCertificateChain(certchain)

    def test_success_dnshost_ip(self):
        """ When DNS Host is an IP, DNS resolution have to fail without error """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        with self.assertLogs(level='INFO') as adnslog:
            acme_dns_tiny.main([self.configs['dnsHostIP'], "--verbose"])
        self.assertIn("INFO:acme_dns_tiny:A and/or AAAA DNS resources not found for configured dns host: we will use either resource found if one exists or directly the DNS Host configuration.",
            adnslog.output)
        certchain = sys.stdout.getvalue()
        
        sys.stdout.close()
        sys.stdout = old_stdout
        
        self.assertCertificateChain(certchain)

    def test_success_san(self):
        """ Successfully issue a certificate via subject alt name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        acme_dns_tiny.main([self.configs['goodSAN'], "--verbose"])
        certchain = sys.stdout.getvalue()
        
        sys.stdout.close()
        sys.stdout = old_stdout
        
        self.assertCertificateChain(certchain)

    def test_success_wildsan(self):
        """ Successfully issue a certificate via wildcard in subject alt name """
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        acme_dns_tiny.main([self.configs['wildSAN']])
        certchain = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = old_stdout

        self.assertCertificateChain(certchain)

    def test_success_cli(self):
        """ Successfully issue a certificate via command line interface """
        certout, err = subprocess.Popen([
            "python3", "acme_dns_tiny.py", self.configs['goodCName'], "--verbose"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        
        certchain = certout.decode("utf8")
        
        self.assertCertificateChain(certchain)

    def test_success_cli_with_csr_option(self):
        """ Successfully issue a certificate via command line interface using CSR option"""
        certout, err = subprocess.Popen([
            "python3", "acme_dns_tiny.py", "--csr", self.configs['cnameCSR'], self.configs['goodCNameWithoutCSR'], "--verbose"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

        certchain = certout.decode("utf8")

        self.assertCertificateChain(certchain)

    def test_weak_key(self):
        """ Let's Encrypt rejects weak keys """
        self.assertRaisesRegex(ValueError,
                               "key too small",
                               acme_dns_tiny.main, [self.configs['weakKey'], "--verbose"])

    def test_account_key_domain(self):
        """ Can't use the account key for the CSR """
        self.assertRaisesRegex(ValueError,
                               "certificate public key must be different than account key",
                               acme_dns_tiny.main, [self.configs['accountAsDomain'], "--verbose"])

    def test_failure_dns_update_tsigkeyname(self):
        """ Fail to update DNS records by invalid TSIG Key name """
        self.assertRaisesRegex(ValueError,
                               "Error updating DNS",
                               acme_dns_tiny.main, [self.configs['invalidTSIGName'], "--verbose"])

    def test_failure_notcompleted_configuration(self):
        """ Configuration file have to be completed """
        self.assertRaisesRegex(ValueError,
                               "Some required settings are missing\.",
                               acme_dns_tiny.main, [self.configs['missingDNS'], "--verbose"])

if __name__ == "__main__":
    unittest.main()
