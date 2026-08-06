# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CARLOS Contributors
# Dev convenience targets. The production install path is the Ansible role
# (no pip on the target host); these targets serve a workstation checkout.
.PHONY: lint type test e2e ansible-checks check

lint:
	ruff check carlos_ctl tests/unit

type:
	mypy carlos_ctl

test:
	pytest tests/unit -q

e2e:
	tests/run-tests.sh

ansible-checks:
	tests/ansible-checks.sh

check: lint type test e2e ansible-checks
