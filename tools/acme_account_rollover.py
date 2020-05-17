#!/usr/bin/env python3
#pylint: disable=multiple-imports, too-many-statements
"""Script to rollover two ACME account keys"""

import sys, argparse, subprocess, json, base64, binascii, re, copy, logging, requests

LOGGER = logging.getLogger("acme_account_rollover")
LOGGER.addHandler(logging.StreamHandler())

def account_rollover(old_accountkeypath, new_accountkeypath, acme_directory, log=LOGGER):
    def _b64(b):
        """"Encodes string as base64 as specified in ACME RFC """
        return base64.urlsafe_b64encode(b).decode("utf8").rstrip("=")

    def _openssl(command, options, communicate=None):
        """Run openssl command line and raise IOError on non-zero return."""
        openssl = subprocess.Popen(["openssl", command] + options,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = openssl.communicate(communicate)
        if openssl.returncode != 0:
            raise IOError("OpenSSL Error: {0}".format(err))
        return out

    def _jws_header(accountkeypath):
        """Creates a JWS header according to a specific account key path."""
        accountkey = _openssl("rsa", ["-in", accountkeypath, "-noout", "-text"])
        pub_hex, pub_exp = re.search(
            r"modulus:\r?\n\s+00:([a-f0-9\:\s]+?)\r?\npublicExponent: ([0-9]+)",
            accountkey.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
        pub_exp = "{0:x}".format(int(pub_exp))
        pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
        jws_header = {
            "alg": "RS256",
            "jwk": {
                "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
                "kty": "RSA",
                "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
            },
            "kid": None
        }
        return jws_header

    def _sign_request(url, keypath, payload, is_inner = False):
        """Signs request with a specific right account key."""
        nonlocal jws_nonce
        if payload == "": # on POST-as-GET, final payload has to be just empty string
            payload64 = ""
        else:
            payload64 = _b64(json.dumps(payload).encode("utf8"))
        if keypath == new_accountkeypath:
            protected = copy.deepcopy(new_jws_header)
        elif keypath == old_accountkeypath:
            protected = copy.deepcopy(old_jws_header)

        if is_inner or url == acme_config["newAccount"]:
            del protected["kid"]
        else:
            del protected["jwk"]

        if not is_inner:
            protected["nonce"] = (jws_nonce
                                  or requests.get(acme_config["newNonce"]).headers['Replay-Nonce'])
        protected["url"] = url
        protected64 = _b64(json.dumps(protected).encode("utf8"))
        signature = _openssl("dgst", ["-sha256", "-sign", keypath],
                             "{0}.{1}".format(protected64, payload64).encode("utf8"))
        signedjws = {
            "protected": protected64, "payload": payload64, "signature": _b64(signature)
        }
        return signedjws

    def _send_signed_request(url, keypath, payload):
        """Sends signed requests to ACME server."""
        nonlocal jws_nonce
        jose = _sign_request(url, keypath, payload)
        try:
            response = requests.post(url, json=jose, headers=joseheaders)
        except requests.exceptions.RequestException as error:
            response = error.response
        finally:
            jws_nonce = response.headers['Replay-Nonce']
        if not response.text:
            return response, json.dumps({})
        return response, response.json()

    # main code
    adtheaders =  {'User-Agent': 'acme-dns-tiny/2.0'}
    joseheaders=copy.deepcopy(adtheaders)
    joseheaders['Content-Type']='application/jose+json'

    log.info("Fetch informations from the ACME directory.")
    directory = requests.get(acme_directory, headers=adtheaders)
    acme_config = directory.json()

    log.info("Parsing current account key...")
    old_jws_header = _jws_header(old_accountkeypath)

    log.info("Parsing new account key...")
    new_jws_header = _jws_header(new_accountkeypath)
    del new_jws_header["kid"]

    jws_nonce = None

    log.info("Ask CA provider account url.")
    http_response, result = _send_signed_request(acme_config["newAccount"], old_accountkeypath, {
        "onlyReturnExisting": True})
    if http_response.status_code == 200:
        old_jws_header["kid"] = http_response.headers["Location"]
        new_jws_header["kid"] = http_response.headers["Location"]
    else:
        raise ValueError("Error looking or account URL: {0} {1}"
                         .format(http_response.status_code, result))

    log.info("Rolls over account key...")
    # The signature by the new key covers the account URL and the old key,
    # signifying a request by the new key holder to take over the account from
    # the old key holder.
    inner_payload = _sign_request(acme_config["keyChange"], new_accountkeypath,
                                  {"account": old_jws_header["kid"],
                                   "oldKey": old_jws_header["jwk"]},
                                  is_inner=True)
    # The signature by the old key covers this request and its signature, and
    # indicates the old key holder's assent to the roll-over request.
    http_response, result = _send_signed_request(acme_config["keyChange"],
                                                 old_accountkeypath, inner_payload)

    if http_response.status_code != 200:
        raise ValueError("Error rolling over account key: {0} {1}"
                         .format(http_response.status_code, result))
    log.info("Account keys rolled over !")

def main(argv):
    """Parse arguments and rollover account keys"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Tiny ACME client to roll over an ACME account key with another one.",
        epilog="""This script *rolls over* ACME account keys.

It will need to have access to the ACME private account keys, so PLEASE READ THROUGH IT!
It's around 150 lines, so it won't take long.

Example: roll over account key from account.key to newaccount.key:
  python3 acme_account_rollover.py \
--current account.key --new newaccount.key \
--acme-directory https://acme-staging-v02.api.letsencrypt.org/directory""")
    parser.add_argument("--current", required=True,
                        help="path to the current private account key")
    parser.add_argument("--new", required=True,
                        help="path to the newer private account key to register")
    parser.add_argument("--acme-directory", required=True,
                        help="ACME directory URL of the ACME server where to remove the key")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR,
                        help="suppress output except for errors")
    args = parser.parse_args(argv)

    LOGGER.setLevel(args.quiet or logging.INFO)
    account_rollover(args.current, args.new, args.acme_directory, log=LOGGER)

if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
