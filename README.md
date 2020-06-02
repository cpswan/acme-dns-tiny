# acme-dns-tiny

[![pipeline status](https://projects.adorsaz.ch/adrien/acme-dns-tiny/badges/master/pipeline.svg)](https://projects.adorsaz.ch/adrien/acme-dns-tiny/commits/master)
[![coverage status](https://projects.adorsaz.ch/adrien/acme-dns-tiny/badges/master/coverage.svg)](https://projects.adorsaz.ch/adrien/acme-dns-tiny/commits/master)

This is a tiny, auditable script that you can throw on any secure machine to
issue and renew [Let's Encrypt](https://letsencrypt.org/) certificates with DNS
validation.

Since it has to have access to your private ACME account key and the
rights to update the DNS records of your DNS server, this code has been designed
to be as tiny as possible (currently less than 300 lines).

The only prerequisites are Python 3, OpenSSL and the dnspython module.

For the dnspython module, be aware that it won't work with release 1.14.0,
because this one have a bug with dynamic DNS updates.
You should either use an older version from dnspython3 module (python3 specific
code) or any release of dnspython module (pyhton2 and python3 merged code) since
1.15.0.

**PLEASE READ THE SOURCE CODE! YOU MUST TRUST IT!
IT HANDLES YOUR ACCOUNT PRIVATE KEYS!**

Note: this script is a fork of the [acme-tiny project](https://github.com/diafygi/acme-tiny)
which uses ACME HTTP verification to create signed certificates.

## Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

## How to use this script

See our the [HowTo Use](https://projects.adorsaz.ch/adrien/acme-dns-tiny/wikis/howto-use) wiki page for main informations.

You may be interested by the [HowTo Setup with BIND9](https://projects.adorsaz.ch/adrien/acme-dns-tiny/wikis/howto-setup-with-bind9)
page too which show a step by step example to set up the script
with a BIND9 DNS server.

Note that, this script can be run on any secure machine which have access to
Internet and your public DNS server.

## Permissions

The biggest problem you'll likely come across while setting up and running this
script is permissions.

You want to limit access for this script to:
* Your account private key
* Your Certificate Signing Request (CSR) file (without your domain key)
* Your configuration file (which contain DNS update secret)

I'd recommend to create a user specifically to run this script and the
above files. This user should *NOT* have access to your domain key!

**BE SURE TO:**
* Backup your account private key (e.g. `account.key`)
* Don't allow this script to be able to read your *domain* private key!
* Don't allow this script to be run as *root*!
* Understand and configure correctly your cron job to do all your needs !
(write it with your preferred language to manage your server)

## Feedback/Contributing

This project has a very, very limited scope and codebase. The project is happy
to receive bug reports and pull requests, but please don't add any new features.
This script must stay under ~400 lines of code to ensure it can be easily
audited by anyone who wants to run it.

If you want to add features for your own setup to make things easier for you,
please do! It's open source, so feel free to fork it and modify as necessary.


