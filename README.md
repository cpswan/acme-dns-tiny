# acme-dns-tiny

[![build status](https://projects.adorsaz.ch/adrien/acme-dns-tiny/badges/master/build.svg)](https://projects.adorsaz.ch/adrien/acme-dns-tiny/commits/master)
[![coverage status](https://projects.adorsaz.ch/adrien/acme-dns-tiny/badges/master/coverage.svg)](https://projects.adorsaz.ch/adrien/acme-dns-tiny/commits/master)

This is a tiny, auditable script that you can throw on your server to issue
and renew [Let's Encrypt](https://letsencrypt.org/) certificates with DNS
validation.

Since it has to have access to your private ACME account key and the
rights to update the DNS records of your DNS server, this code has been designed
to be as tiny as possible (currently less than 250 lines).

The only prerequisites are python (especially the dnspython module) and openssl.

**PLEASE READ THE SOURCE CODE! YOU MUST TRUST IT! IT HANDLES YOUR ACCOUNT PRIVATE KEYS!**

Note: this script is a fork of the [acme-tiny project](https://github.com/diafygi/acme-tiny)
which uses ACME HTTP verification to create signed certificates.

## Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

## How to use this script

If you already have a Let's Encrypt issued certificate and just want to renew,
you should only have to do Steps 3 and 6.

### Step 1: Create a Let's Encrypt account private key (if you haven't already)

You must have a public key registered with Let's Encrypt and sign your requests
with the corresponding private key. If you don't understand what I just said,
this script likely isn't for you! Please use the official Let's Encrypt
[client](https://github.com/letsencrypt/letsencrypt).
To accomplish this you need to initially create a key, that can be used by
acme-tiny, to register a account for you and sign all following requests.

```
openssl genrsa 4096 > account.key
```

#### Use existing Let's Encrypt key

Alternatively you can convert your key, previously generated by the original
Let's Encrypt client.

The private account key from the Let's Encrypt client is saved in the
[JWK](https://tools.ietf.org/html/rfc7517) format. `acme-tiny` is using the PEM
key format. To convert the key, you can use the tool
[conversion script](https://gist.github.com/JonLundy/f25c99ee0770e19dc595)
by JonLundy:

```sh
# Download the script
curl "https://gist.githubusercontent.com/JonLundy/f25c99ee0770e19dc595/raw/6035c1c8938fae85810de6aad1ecf6e2db663e26/conv.py" > conv.py

# Copy your private key to your working directory
cp /etc/letsencrypt/accounts/acme-v01.api.letsencrypt.org/directory/<id>/private_key.json private_key.json

# Create a DER encoded private key
openssl asn1parse -noout -out private_key.der -genconf <(python conv.py private_key.json)

# Convert to PEM
openssl rsa -in private_key.der -inform der > account.key
```

### Step 2: Create a certificate signing request (CSR) for your domains.

The ACME protocol (what Let's Encrypt uses) requires a CSR file to be submitted
to it, even for renewals. You can use the same CSR for multiple renewals.

NOTE: you can't use your account private key as your domain private key!

```
#generate a domain private key (if you haven't already)
openssl genrsa 4096 > domain.key
```

```
#for a single domain
openssl req -new -sha256 -key domain.key -subj "/CN=example.org" > domain.csr

#for multiple domains (use this one if you want both www.example.org and example.org)
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.org,DNS:www.example.org")) > domain.csr
```

### Step 3: Make your DNS server allows dynamic updates

You must prove you own the domains you want a certificate for, so Let's Encrypt
requires you host some DNS resource records.

This script will generate and write those DNS records to your DNS server by
use of DNS dynamic message updates.

So you have to configure your DNS server to allow dynamic DNS
updates and create a TSIG key which will give rights to perform updates.

The configuration of the script will need:
* the TSIG key name and value
* the algorithm used for TSIG key (hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384 or hmac-512; list of algoithm depends on knowe ones by dnspython module)
* the DNS zone to update
* the address and the port of the DNS server

The simplest way to configure the script is to copy the `example.ini` file
from this repository and update values as needed.

**Be careful! Set read permissions correctly on the configuration file, because
it will contain the key authorized to modify your DNS configuration !**

### Step 4: Get a signed certificate!

Now that you have setup your server and generated all the needed files, run this
script on a computer containing your private account key, the CSR and the configuration.

```
python acme_dns_tiny.py example.ini > ./chain.pem
```

If every thing was ok, chain.crt contains your signed certificate followed by the
CA's certificate which signed yours.

### Step 5: Install the certificate

The certificate chain that is output by this script can be used along
with your private key to run any service on your server which need TSL encryption.
You need to include both in the TLS settings of your services.

### Step 6: Setup an auto-renew cronjob

Congrats! Your server is now using TLS! Unfortunately, Let's Encrypt
certificates only last for 90 days, so you need to renew them often. No worries!
It's automated! Just make a bash script and add it to your crontab (see below
for example script).

Example of a skeleton for `renew_cert.sh` script:
```sh
#!/bin/bash

# Configuration
# You should use another directory as /tmp could be destroyed regularly
WORKINGDIR="/tmp/acme-dns-tiny"

# Pre run script: configure a secure workspace using ACL POSIX
mkdir -p ${WORKINGDIR}
setfacl -m "default:other:--- , other:---" ${WORKINGDIR}

# You should also add code to create backup of older certificates
# You may need code to handle HPKP (key pining in HTTP) updates
# You may need to update DANE (key pining in DNS) too
# With HPKP and DANE, you should also consider your automatic key rollover
# which will need to update the CSR file and/or your DNS DANE records.

# Run the script
python /path/to/acme_dns_tiny.py example.ini > ${WORKINGDIR}/chain.pem || exit


# Post run script

# You should reload each service using TLS
```

Then you'll need to configure a cron job to execute this script regularly (think
to set random minutes to avoid to DDOS the CA servers).

## Permissions

The biggest problem you'll likely come across while setting up and running this
script is permissions. You want to limit access to your account private key, your
CSR and your configuration file. I'd recommend creating a user
specifically for handling this script, the account private key, the CSR and
the DNS key. Then add the ability for that user to write to your installed
certificate file (e.g. `/path/to/chain.pem`) and reload your services. That
way, the cron job will do its thing, overwrite your old certificate, and
reload your webserver without having permission to do anything else.

**BE SURE TO:**
* Backup your account private key (e.g. `account.key`)
* Don't allow this script to be able to read your *domain* private key!
* Don't allow this script to be run as *root*!
* Understand and configure correctly your cron job to do all your needs !
(if you don't know bash, write it in your preferred language to manage your
server)

## Feedback/Contributing

This project has a very, very limited scope and codebase. The project is happy
to receive bug reports and pull requests, but please don't add any new features.
This script must stay under 250 lines of code to ensure it can be easily audited
by anyone who wants to run it.

If you want to add features for your own setup to make things easier for you,
please do! It's open source, so feel free to fork it and modify as necessary.
