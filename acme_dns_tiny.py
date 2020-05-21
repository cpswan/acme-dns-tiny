#!/usr/bin/env python3
#pylint: disable=multiple-imports
"""ACME client to met DNS challenge and receive TLS certificate"""
import argparse, base64, binascii, configparser, copy, hashlib, json, logging
import re, sys, subprocess, time
import requests, dns.resolver, dns.tsigkeyring, dns.update

LOGGER = logging.getLogger('acme_dns_tiny')
LOGGER.addHandler(logging.StreamHandler())

def _base64(text):
    """"Encodes string as base64 as specified in the ACME RFC."""
    return base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")

def _openssl(command, options, communicate=None):
    """Run openssl command line and raise IOError on non-zero return."""
    openssl = subprocess.Popen(["openssl", command] + options,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = openssl.communicate(communicate)
    if openssl.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out

def _get_signature(accountkeypath):
    """Parses account key to create user's Json Web Signature"""
    accountkey = _openssl("rsa", ["-in", accountkeypath, "-noout", "-text"])
    pub_hex, pub_exp = re.search(
        r"modulus:\r?\n\s+00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
        accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    jws_header = {
        "alg": "RS256",
        "jwk": {
            "e": _base64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _base64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
        },
        "kid": None,
    }
    accountkey_json = json.dumps(jws_header["jwk"], sort_keys=True, separators=(",", ":"))
    jwk_thumbprint = _base64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    return {"header": jws_header, "thumbprint": jwk_thumbprint}

def _get_dns_config(config, log):
    """Configure DNS resolver and keyring"""
    keyring = dns.tsigkeyring.from_text(
        {config["TSIGKeyring"]["KeyName"]: config["TSIGKeyring"]["KeyValue"]})
    resolver = dns.resolver.Resolver(configure=False)
    resolver.retry_servfail = True
    nameserver = []
    try:
        nameserver = [ipv4_rrset.to_text() for ipv4_rrset in
                      dns.resolver.query(config["DNS"]["Host"], rdtype="A")]
        nameserver = nameserver + [ipv6_rrset.to_text() for ipv6_rrset in
                                   dns.resolver.query(config["DNS"]["Host"], rdtype="AAAA")]
    except dns.exception.DNSException:
        log.info("A and/or AAAA DNS resources not found for configured dns host: we will use \
either resource found if one exists or directly the DNS Host configuration.")
    if not nameserver:
        nameserver = [config["DNS"]["Host"]]
    resolver.nameservers = nameserver

    return {"keyring": keyring, "resolver": resolver, "TTL": config["DNS"].getint("TTL")}

def _update_dns(config, keyring, rrset, action):
    """Updates DNS resource by adding or deleting resource."""
    algorithm = dns.name.from_text("{0}".format(config["TSIGKeyring"]["Algorithm"].lower()))
    dns_update = dns.update.Update(config["DNS"]["zone"],
                                   keyring=keyring, keyalgorithm=algorithm)
    if action == "add":
        dns_update.add(rrset.name, rrset)
    elif action == "delete":
        dns_update.delete(rrset.name, rrset)
    response = dns.query.tcp(dns_update, config["DNS"]["Host"], config.getint("DNS", "Port"))
    return response

def _get_domain_names(config):
    """Read CSR to retrieve domain names to validate"""
    csr = _openssl("req",
                   ["-in", config["acmednstiny"]["CSRFile"], "-noout", "-text"]).decode("utf8")
    domain_names = set()
    common_name = re.search(r"Subject:.*?\s+?CN\s*?=\s*?([^\s,;/]+)", csr)
    if common_name is not None:
        domain_names.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: \r?\n +([^\r\n]+)\r?\n",
                                  csr, re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domain_names.add(san[4:])
    if len(domain_names) == 0:
        raise ValueError("Didn't find any domain to validate in the provided CSR.")
    return domain_names

def _send_signed_request(url, payload, acme_config):
    """Sends signed requests to ACME server."""
    headers = copy.deepcopy(acme_config["headers"])
    headers['Content-Type'] = 'application/jose+json'

    if payload == "": # on POST-as-GET, final payload has to be just empty string
        payload64 = ""
    else:
        payload64 = _base64(json.dumps(payload).encode("utf8"))
    protected = copy.deepcopy(acme_config["signature"]["header"])
    protected["nonce"] = (acme_config.pop("nonce", None)
                          or requests.get(acme_config["directory"]["newNonce"])
                          .headers['Replay-Nonce'])
    protected["url"] = url
    if url == acme_config["directory"]["newAccount"]:
        del protected["kid"]
    else:
        del protected["jwk"]
    protected64 = _base64(json.dumps(protected).encode("utf8"))
    jose_signature = _openssl("dgst", ["-sha256", "-sign", acme_config["account_key_file"]],
                              "{0}.{1}".format(protected64, payload64).encode("utf8"))
    jose = {"protected": protected64, "payload": payload64,
            "signature": _base64(jose_signature)}
    try:
        response = requests.post(url, json=jose, headers=headers)
    except requests.exceptions.RequestException as error:
        response = error.response
    finally:
        acme_config["nonce"] = response.headers['Replay-Nonce']
    if not response.text:
        return response, json.dumps({})
    return {"response": response, "json": response.json()}

def _acme_register_account(config, log, acme_config):
    account_request = {}
    terms_service = acme_config.get("meta", {}).get("termsOfService", "")
    if terms_service:
        account_request["termsOfServiceAgreed"] = True
        log.warning(
            "Terms of service exists and will be automatically agreed, please read them: %s",
            terms_service)
    account_request["contact"] = config["acmednstiny"].get("Contacts", "").split(';')
    if account_request["contact"] == [""]:
        del account_request["contact"]

    result = _send_signed_request(acme_config["directory"]["newAccount"],
                                  account_request, acme_config)
    if result["response"].status_code == 201:
        acme_config["signature"]["header"]["kid"] = result["response"].headers['Location']
        log.info("  - Registered a new account: '%s'", acme_config["signature"]["header"]["kid"])
    elif result["response"].status_code == 200:
        acme_config["signature"]["header"]["kid"] = result["response"].headers['Location']
        log.debug("  - Account is already registered: '%s'",
                  acme_config["signature"]["header"]["kid"])

        result = _send_signed_request(acme_config["signature"]["header"]["kid"], {}, acme_config)
    else:
        raise ValueError("Error registering account: {0} {1}"
                         .format(result["response"].status_code, result["json"]))

    log.info("Update contact information if needed.")
    if ("contact" in account_request
            and set(account_request["contact"]) != set(result["json"]["contact"])):
        result = _send_signed_request(acme_config["signature"]["header"]["kid"],
                                      account_request, acme_config)
        if result["response"].status_code == 200:
            log.debug("  - Account updated with latest contact informations.")
        else:
            raise ValueError("Error registering updates for the account: {0} {1}"
                             .format(result["response"].status_code, result["json"]))

def _acme_request_order(log, domain_names, acme_config):
    new_order = {"identifiers": [{"type": "dns", "value": domain} for domain in domain_names]}
    result = _send_signed_request(acme_config["directory"]["newOrder"], new_order, acme_config)
    order = result["response"]["json"]
    if result["response"].status_code == 201:
        location = result["response"].headers['Location']
        log.debug("  - Order received: %s", location)
        if order["status"] != "pending" and order["status"] != "ready":
            raise ValueError("Order status is neither pending neither ready: {0}".format(order))
    elif (result["response"].status_code == 403
          and order["type"] == "urn:ietf:params:acme:error:userActionRequired"):
        raise ValueError("Order creation failed ({0}). Read Terms of Service ({1}), \
then follow your CA instructions: {2}"
                         .format(order["detail"], result["response"].headers['Link'],
                                 order["instance"]))
    else:
        raise ValueError("Error getting new Order: {0} {1}"
                         .format(result["response"].status_code, order))
    return {"order": order, "location": location}

def _acme_prepare_challenge(authz, config, dns_config, acme_config, log):
    """Prepare DNS resources to meet challenge for the authz"""
    result = _send_signed_request(authz, "", acme_config)
    if result["response"].status_code != 200:
        raise ValueError("Error fetching challenges: {0} {1}"
                         .format(result["response"].status_code, result["json"]))
    authorization = result["json"]
    domain = authorization["identifier"]["value"]

    log.info("Install DNS TXT resource for domain: %s", domain)
    challenge = [c for c in authorization["challenges"] if c["type"] == "dns-01"][0]
    token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
    keyauthorization = "{0}.{1}".format(token, acme_config["signature"]["thumbprint"])
    keydigest64 = _base64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
    dnsrr_domain = "_acme-challenge.{0}.".format(domain)
    try:# A CNAME resource can be used for advanced TSIG configuration
        # The CNAME target has to be of "non-CNAME" type to be able to add TXT records aside it
        dnsrr_domain = [response.to_text()
                        for response in dns_config["resolver"]
                        .query(dnsrr_domain, rdtype="CNAME")][0]
        log.info("  - A CNAME resource has been found for this domain, will install TXT on %s",
                 dnsrr_domain)
    except dns.exception.DNSException as dnsexception:
        log.debug("  - Not any CNAME resource has been found for this domain (%s), \
will install TXT directly on %s", dnsrr_domain, type(dnsexception).__name__)
    dnsrr_set = dns.rrset.from_text(dnsrr_domain, config["DNS"].getint("TTL"),
                                    "IN", "TXT", '"{0}"'.format(keydigest64))
    try:
        _update_dns(config, dns_config["keyring"], dnsrr_set, "add")
    except dns.exception.DNSException as dnsexception:
        raise ValueError("Error updating DNS records: {0} : {1}"
                         .format(type(dnsexception).__name__, str(dnsexception)))
    return {"challenge": challenge, "domain": domain,
            "keyauthorization": keyauthorization, "dnsrr_set": dnsrr_set, "text": keydigest64}

def _verify_challenge(challenge, dns_config, log):
    """Self verify if challenge is well met"""
    log.info("Wait for 1 TTL (%s seconds) to ensure DNS cache is cleared.", dns_config["TTL"])
    time.sleep(dns_config["TTL"])
    resolver = dns_config["resolver"]
    challenge_verified = False
    number_check_fail = 1
    while challenge_verified is False:
        try:
            log.debug('Self test (try: %s): Check resource with value "%s" exits on \
nameservers: %s', number_check_fail, challenge["text"], resolver.nameservers)
            for response in resolver.query(challenge["dnsrr_set"].name, rdtype="TXT").rrset:
                log.debug("  - Found value %s", response.to_text())
                challenge_verified = (challenge_verified
                                      or response.to_text() == '"{0}"'.format(challenge["text"]))
        except dns.exception.DNSException as dnsexception:
            log.debug("  - Will retry as a DNS error occurred while checking challenge: \
%s : %s", type(dnsexception).__name__, dnsexception)
        finally:
            if challenge_verified is False:
                if number_check_fail >= 10:
                    raise ValueError("Error checking challenge, value not found: {0}"
                                     .format(challenge["text"]))
                number_check_fail = number_check_fail + 1
                time.sleep(dns_config["TTL"])

def _acme_validate_challenge(challenge, acme_config, log):
    result = _send_signed_request(challenge["challenge"]["url"],
                                  {"keyAuthorization": challenge["keyauthorization"]},
                                  acme_config)
    if result["response"].status_code != 200:
        raise ValueError("Error triggering challenge: {0} {1}"
                         .format(result["response"].status_code, result["json"]))
    while True:
        result = _send_signed_request(challenge["challenge"]["url"], "", acme_config)
        if result["response"].status_code != 200:
            raise ValueError("Error during challenge validation: {0} {1}".format(
                result["response"].status_code, result["json"]))
        if result["json"]["status"] == "pending":
            time.sleep(2)
        elif result["json"]["status"] == "valid":
            log.info("ACME has verified challenge for domain: %s", challenge["domain"])
            break
        else:
            raise ValueError("Challenge for domain {0} did not pass: {1}".format(
                challenge["domain"], result["json"]))

def _acme_finalize_order(order, config, acme_config, log):
    csr_der = _base64(_openssl("req", ["-in", config["acmednstiny"]["CSRFile"],
                                       "-outform", "DER"]))
    result = _send_signed_request(order["order"]["finalize"], {"csr": csr_der}, acme_config)
    if result["response"].status_code != 200:
        raise ValueError("Error while sending the CSR: {0} {1}"
                         .format(result["response"].status_code, result["json"]))

    while True:
        result = _send_signed_request(order["location"], "", acme_config)

        if result["json"]["status"] == "processing":
            if result["response"].headers["Retry-After"]:
                time.sleep(result["response"].headers["Retry-After"])
            else:
                time.sleep(2)
        elif result["json"]["status"] == "valid":
            log.info("Order finalized!")
            break
        else:
            raise ValueError("Finalizing order, but got errors: {1}".format(result["json"]))

def get_crt(config, log=LOGGER):
    """Get ACME certificate by resolving DNS challenge"""
    acme_config = {
        "account_key_file": config["acmednstiny"]["AccountKeyFile"],
        "nonce": None,
        "headers": {'User-Agent': 'acme-dns-tiny/2.1',
                    'Accept-Language': config["acmednstiny"].get("Language", "en")}}

    log.info("Fetch informations from the ACME directory.")
    acme_config["directory"] = requests.get(config["acmednstiny"]["ACMEDirectory"],
                                            headers=acme_config["headers"]).json()

    log.info("Prepare DNS keyring and resolver.")
    dns_config = _get_dns_config(config, log)

    log.info("Read CSR to find domain_names to validate.")
    domain_names = _get_domain_names(config)

    log.info("Read account key.")
    acme_config["signature"] = _get_signature(config["acmednstiny"]["AccountKeyFile"])

    log.info("Register ACME Account to get the key identifier.")
    _acme_register_account(config, log, acme_config)

    log.info("Request to the ACME server an order to validate domain_names.")
    order = _acme_request_order(log, domain_names, acme_config)

    for authz in order["order"]["authorizations"]:
        if order["order"]["status"] == "ready":
            log.info("No challenge to process: order is already ready.")
            break

        log.info("Process challenge for authorization: %s", authz)
        challenge = _acme_prepare_challenge(authz, config, dns_config, acme_config, log)

        try:
            log.info("Self verify if challenge is well installed.")
            _verify_challenge(challenge, dns_config, log)
            log.info("Asking ACME server to validate challenge.")
            _acme_validate_challenge(challenge, acme_config, log)
        finally:
            _update_dns(config, dns_config["keyring"], challenge["dnsrr_set"], "delete")

    log.info("Request to finalize the order (all chalenge have been completed)")
    _acme_finalize_order(order, config, acme_config, log)

    acme_config["signature"]["header"]['Accept'] = config["acmednstiny"].get(
        "CertificateFormat", 'application/pem-certificate-chain')
    result = _send_signed_request(order["order"]["certificate"], "", acme_config)
    if result["response"].status_code != 200:
        raise ValueError("Finalizing order {0} got errors: {1}"
                         .format(result["response"].status_code, result["json"]))

    if 'link' in result["response"].headers:
        log.info("  - Certificate links given by server: %s", result["response"].headers['link'])

    log.info("Certificate signed and chain received: %s", order["order"]["certificate"])
    return result["response"].text

def main(argv):
    """Parse arguments and get certificate."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME client to get TLS certificate by responding to DNS challenges.",
        epilog="""As the script requires access to your private ACME account key and dns server,
so PLEASE READ THROUGH IT (it won't take too long, it's a one-file script) !

Example: requests certificate chain and store it in chain.crt
  python3 acme_dns_tiny.py ./example.ini > chain.crt

See example.ini file to configure correctly this script."""
    )
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR,
                        help="show only errors on stderr")
    parser.add_argument("--verbose", action="store_const", const=logging.DEBUG,
                        help="show all debug informations on stderr")
    parser.add_argument("--csr",
                        help="specifies CSR file path to use instead of the CSRFile option \
from the configuration file.")
    parser.add_argument("configfile", help="path to your configuration file")
    args = parser.parse_args(argv)

    config = configparser.ConfigParser()
    config.read_dict({
        "acmednstiny": {"ACMEDirectory": "https://acme-staging-v02.api.letsencrypt.org/directory"},
        "DNS": {"Port": 53, "TTL": 10}})
    config.read(args.configfile)

    if args.csr:
        config.set("acmednstiny", "csrfile", args.csr)

    if (set(["accountkeyfile", "csrfile", "acmedirectory"]) - set(config.options("acmednstiny"))
            or set(["keyname", "keyvalue", "algorithm"]) - set(config.options("TSIGKeyring"))
            or set(["zone", "host", "port", "ttl"]) - set(config.options("DNS"))):
        raise ValueError("Some required settings are missing.")

    LOGGER.setLevel(args.verbose or args.quiet or logging.INFO)
    signed_crt = get_crt(config, log=LOGGER)
    sys.stdout.write(signed_crt)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
