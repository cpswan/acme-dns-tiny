.PHONY: requirements unit_test_acme_dns_tiny_success_san unit_test_acme_account_rollover unit_test_acme_account_deactivate

DEFAULT: requirements

unit_test_acme_dns_tiny_success_san:
	python3 -m unittest tests.test_acme_dns_tiny.TestACMEDNSTiny.test_success_san

unit_test_acme_account_rollover:
	python3 -m unittest tests.staging_test_acme_account_rollover.TestACMEAccountRollover.test_success_account_rollover

unit_test_acme_account_deactivate:
	python3 -m unittest tests.staging_test_acme_account_deactivate.TestACMEAccountDeactivate.test_success_account_deactivate

unit_test_all_with_coverage:
	python3-coverage run --source ./ -m unittest -v tests.unit_test_acme_dns_tiny tests.staging_test_acme_dns_tiny tests.staging_test_acme_account_rollover tests.staging_test_acme_account_deactivate
	python3-coverage report --include=acme_dns_tiny.py,tools/acme_account_rollover.py,tools/acme_account_deactivate.py
	python3-coverage html

requirements:
	pip3 install --user --upgrade -r tests/requirements.txt

