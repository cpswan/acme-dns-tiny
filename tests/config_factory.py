"""Create real temporary ACME dns tiny configurations to run tests with real server"""
import os
import configparser
from tempfile import NamedTemporaryFile
from subprocess import Popen

# domain with server.py running on it for testing
DOMAIN = os.getenv("GITLABCI_DOMAIN")
ACMEDIRECTORY = os.getenv("GITLABCI_ACMEDIRECTORY_V2",
                          "https://acme-staging-v02.api.letsencrypt.org/directory")
DNSHOST = os.getenv("GITLABCI_DNSHOST")
DNSHOSTIP = os.getenv("GITLABCI_DNSHOSTIP")
DNSZONE = os.getenv("GITLABCI_DNSZONE")
DNSPORT = os.getenv("GITLABCI_DNSPORT", "53")
DNSTTL = os.getenv("GITLABCI_DNSTTL", "10")
TSIGKEYNAME = os.getenv("GITLABCI_TSIGKEYNAME")
TSIGKEYVALUE = os.getenv("GITLABCI_TSIGKEYVALUE")
TSIGALGORITHM = os.getenv("GITLABCI_TSIGALGORITHM")
CONTACT = os.getenv("GITLABCI_CONTACT")


def generate_config():
    """Generate basic acme-dns-tiny configuration"""
    # Account key
    account_key = NamedTemporaryFile(delete=False)
    Popen(["openssl", "genrsa", "-out", account_key.name, "2048"]).wait()

    # Domain key and CSR
    domain_key = NamedTemporaryFile(delete=False)
    domain_csr = NamedTemporaryFile(delete=False)
    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key.name,
           "-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr.name]).wait()

    # acme-dns-tiny configuration
    parser = configparser.ConfigParser()
    parser.read("./example.ini")
    parser["acmednstiny"]["AccountKeyFile"] = account_key.name
    parser["acmednstiny"]["CSRFile"] = domain_csr.name
    parser["acmednstiny"]["ACMEDirectory"] = ACMEDIRECTORY
    if CONTACT:
        parser["acmednstiny"]["Contacts"] = "mailto:{0}".format(CONTACT)
    elif "Contacts" in parser:
        del parser["acmednstiny"]["Contacts"]
    parser["TSIGKeyring"]["KeyName"] = TSIGKEYNAME
    parser["TSIGKeyring"]["KeyValue"] = TSIGKEYVALUE
    parser["TSIGKeyring"]["Algorithm"] = TSIGALGORITHM
    parser["DNS"]["Host"] = DNSHOST
    parser["DNS"]["Port"] = DNSPORT
    parser["DNS"]["Zone"] = DNSZONE
    parser["DNS"]["TTL"] = DNSTTL

    return account_key.name, domain_key.name, domain_csr.name, parser


def generate_acme_dns_tiny_unit_test_config():
    """Genereate acme_dns_tiny configurations used for unit tests"""
    # Configuration missing DNS section
    _, domain_key, _, config = generate_config()
    os.remove(domain_key)

    missing_dns = NamedTemporaryFile(delete=False)
    config["DNS"] = {}
    with open(missing_dns.name, 'w') as configfile:
        config.write(configfile)

    return {"missing_dns": missing_dns.name}


def generate_acme_dns_tiny_config():  # pylint: disable=too-many-locals,too-many-statements
    """Generate acme_dns_tiny configuration with account and domain keys"""
    # Simple configuration with good options
    account_key, domain_key, _, config = generate_config()
    os.remove(domain_key)

    good_cname = NamedTemporaryFile(delete=False)
    with open(good_cname.name, 'w') as configfile:
        config.write(configfile)

    # Simple configuration with good options, without contacts field
    account_key, domain_key, _, config = generate_config()
    os.remove(domain_key)

    config.remove_option("acmednstiny", "Contacts")

    good_cname_without_contacts = NamedTemporaryFile(delete=False)
    with open(good_cname_without_contacts.name, 'w') as configfile:
        config.write(configfile)

    # Simple configuration without CSR in configuration (will be passed as argument)
    account_key, domain_key, cname_csr, config = generate_config()
    os.remove(domain_key)

    config.remove_option("acmednstiny", "CSRFile")

    good_cname_without_csr = NamedTemporaryFile(delete=False)
    with open(good_cname_without_csr.name, 'w') as configfile:
        config.write(configfile)

    # Configuration with CSR containing a wildcard domain
    account_key, domain_key, domain_csr, config = generate_config()

    Popen(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", domain_key,
           "-subj", "/CN=*.{0}".format(DOMAIN), "-out", domain_csr]).wait()
    os.remove(domain_key)

    wild_cname = NamedTemporaryFile(delete=False)
    with open(wild_cname.name, 'w') as configfile:
        config.write(configfile)

    # Configuration with IP as DNS Host
    account_key, domain_key, _, config = generate_config()
    os.remove(domain_key)

    config["DNS"]["Host"] = DNSHOSTIP

    dns_host_ip = NamedTemporaryFile(delete=False)
    with open(dns_host_ip.name, 'w') as configfile:
        config.write(configfile)

    # Configuration with CSR using subject alt-name domain instead of CN (common name)
    account_key, domain_key, domain_csr, config = generate_config()

    san_conf = NamedTemporaryFile(delete=False)
    with open("/etc/ssl/openssl.cnf", 'r') as opensslcnf:
        san_conf.write(opensslcnf.read().encode("utf8"))
    san_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:www.{0}\n".format(DOMAIN).encode("utf8"))
    san_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key,
           "-subj", "/", "-reqexts", "SAN", "-config", san_conf.name,
           "-out", domain_csr]).wait()
    os.remove(san_conf.name)
    os.remove(domain_key)

    good_san = NamedTemporaryFile(delete=False)
    with open(good_san.name, 'w') as configfile:
        config.write(configfile)

    # Configuration with CSR containing a wildcard domain inside subjetcAltName
    account_key, domain_key, domain_csr, config = generate_config()

    wild_san_conf = NamedTemporaryFile(delete=False)
    with open("/etc/ssl/openssl.cnf", 'r') as opensslcnf:
        wild_san_conf.write(opensslcnf.read().encode("utf8"))
    wild_san_conf.write("\n[SAN]\nsubjectAltName=DNS:{0},DNS:*.{0}\n".format(DOMAIN).encode("utf8"))
    wild_san_conf.seek(0)
    Popen(["openssl", "req", "-new", "-sha256", "-key", domain_key,
           "-subj", "/", "-reqexts", "SAN", "-config", wild_san_conf.name,
           "-out", domain_csr]).wait()
    os.remove(wild_san_conf.name)
    os.remove(domain_key)

    wild_san = NamedTemporaryFile(delete=False)
    with open(wild_san.name, 'w') as configfile:
        config.write(configfile)

    # Bad configuration with weak 1024 bit account key
    account_key, domain_key, _, config = generate_config()
    os.remove(domain_key)

    Popen(["openssl", "genrsa", "-out", account_key, "1024"]).wait()

    weak_key = NamedTemporaryFile(delete=False)
    with open(weak_key.name, 'w') as configfile:
        config.write(configfile)

    # Bad configuration with account key as domain key
    account_key, domain_key, domain_csr, config = generate_config()
    os.remove(domain_key)

    # Create a new CSR signed with the account key instead of domain key
    Popen(["openssl", "req", "-new", "-sha256", "-key", account_key,
           "-subj", "/CN={0}".format(DOMAIN), "-out", domain_csr]).wait()

    account_as_domain = NamedTemporaryFile(delete=False)
    with open(account_as_domain.name, 'w') as configfile:
        config.write(configfile)

    # Create config parser from the good default config to generate custom configs
    account_key, domain_key, _, config = generate_config()
    os.remove(domain_key)

    invalid_tsig_name = NamedTemporaryFile(delete=False)
    config["TSIGKeyring"]["KeyName"] = "{0}.invalid".format(TSIGKEYNAME)
    with open(invalid_tsig_name.name, 'w') as configfile:
        config.write(configfile)

    return {
        # configs
        "good_cname": good_cname.name,
        "good_cname_without_contacts": good_cname_without_contacts.name,
        "good_cname_without_csr": good_cname_without_csr.name,
        "wild_cname": wild_cname.name,
        "dns_host_ip": dns_host_ip.name,
        "good_san": good_san.name,
        "wild_san": wild_san.name,
        "weak_key": weak_key.name,
        "account_as_domain": account_as_domain.name,
        "invalid_tsig_name": invalid_tsig_name.name,
        # cname CSR file to use with good_cname_without_csr as argument
        "cname_csr": cname_csr,
    }


def generate_acme_account_rollover_config():
    """Generate config for acme_account_rollover script"""
    # Old account key is directly created by the config generator
    old_account_key, domain_key, _, config = generate_config()
    os.remove(domain_key)

    # New account key
    new_account_key = NamedTemporaryFile(delete=False)
    Popen(["openssl", "genrsa", "-out", new_account_key.name, "2048"]).wait()

    rollover_account = NamedTemporaryFile(delete=False)
    with open(rollover_account.name, 'w') as configfile:
        config.write(configfile)

    return {
        # config and keys (returned to keep files on system)
        "config": rollover_account.name,
        "old_account_key": old_account_key,
        "new_account_key": new_account_key.name
    }


def generate_acme_account_deactivate_config():
    """Generate config for acme_account_deactivate script"""
    # Account key is created by the by the config generator
    account_key, domain_key, _, config = generate_config()
    os.remove(domain_key)

    deactivate_account = NamedTemporaryFile(delete=False)
    with open(deactivate_account.name, 'w') as configfile:
        config.write(configfile)

    return {
        "config": deactivate_account.name,
        "key": account_key
    }
