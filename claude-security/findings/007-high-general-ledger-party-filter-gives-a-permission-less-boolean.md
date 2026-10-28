# General Ledger party filter gives a permission-less boolean oracle over any DocType's fields

| Field | Value |
|---|---|
| ID | `find_015fxt17QNnXJX3r2xVrZm4M` |
| Severity | **High** |
| Status | open |
| CWE | CWE-204 — Observable Response Discrepancy |
| Created | 2026-10-27T21:20:49.781865Z |
| Claude Security | https://claude.ai/security/findings/find_015fxt17QNnXJX3r2xVrZm4M |

## Description

In `erpnext/accounts/report/general_ledger/general_ledger.py`, `execute()` (lines `45`-`50`) passes the request's `party` filter through `frappe.parse_json`, which leaves the type of each list item unchecked. It then calls `validate_party()` (lines `99`-`105`), which runs `frappe.db.exists(party_type, d)` for every item and throws `Invalid {party_type}: {d}` on the first one that does not match. `party_type` is limited to party doctypes only in the browser (`general_ledger.js:63-67`, an Autocomplete of `frappe.boot.party_account_types`). The Report record declares no server-side filters (`general_ledger.json:17`), so the server never checks that `party_type` is a party doctype, that the user may read it, or that each `party` item is a plain name. `frappe.db.exists` does no permission check. Called with a dict as its second argument, it treats the dict as a set of query filters. ERPNext itself relies on this form, with operators, in its pinned framework (for example `company.py:353`). So each `party` item can be a filter such as `{"name": "HR-EMP-00001", "ctc": [">", 100000]}`. The error text names the first item that failed, which turns each request into a yes/no answer: does any row of the chosen table match the attacker's filter? Repeating it with `>`/`<` or `like` prefixes reads back, bit by bit, any column of any DocType table that is not a Password field, whatever the user's permissions. One example is `Employee`, a legitimate party type, on which `Accounts User` holds only `select` and `Auditor` holds nothing (`employee.json:890-897`). The attacker can read `ctc` (salary), `bank_ac_no`, `iban`, `passport_number` and `date_of_birth`. The same works for other companies' documents that the user is kept from by User Permissions. Checking a plain name (the candidate's original claim) adds little, because the framework's REST API already separates missing documents from forbidden ones. The real gain is the filter-dict form. `set_account_currency()` (lines `127`-`140`) also loads `default_currency` from the chosen doctype and record without a permission check, a minor additional leak. Assumption: Frappe `>=17.0.0-dev,<18.0.0` (`pyproject.toml`, not in the checkout) keeps the documented `frappe.db.exists(doctype, filters_dict)` behaviour (a permission-less `get_value` with `ignore=True`). It is also assumed that `frappe.desk.query_report.run` checks only the report's roles, `report` permission on `GL Entry` and the Report's (empty) filter table.

## Assessment

The attacker is a logged-in desk user with `Accounts User`, `Accounts Manager` or `Auditor`, matching the threat model's "low-privilege authenticated employees". They call `/api/method/frappe.desk.query_report.run` for `General Ledger` with any `company` and dates, `party_type` set to the target DocType (e.g. `Employee`), and `party=[{"name":"HR-EMP-00001","ctc":[">",N]}, "zz-missing"]`. If the error names the dict, the filter did not match; if it names `zz-missing`, it did. Binary search over repeated requests recovers the value. No other user takes part.

Impact: The attacker can recover the value of any non-Password column in any DocType table, whatever their read permission or User Permissions. Examples are employees' salary (`ctc`), bank account numbers, IBANs and passport numbers, and other companies' customers, invoices and bank data. Password fields stored in `__Auth` are out of reach. Nothing is modified, and each request costs the load of one report call.

## Recommendation

(1) `validate_party()` passes caller-supplied `party` items straight to `frappe.db.exists`, which accepts filter dicts and checks no permissions. Its error then names the first item that did not match, which turns the report into a boolean query oracle over arbitrary tables and columns.

Fix criteria: Each `party` item must be rejected unless it is a plain string name. `party_type` must be one of the supported party doctypes. The user must hold read permission on that doctype and on each named party before any lookup. Otherwise the response must be identical whether or not a record exists. Verify: sending `party_type=Employee` with a filter-dict item is refused, and an unreadable name gives the same response whether it exists or not.

(2) `set_account_currency()` reads `default_currency` from the caller-chosen doctype and record with `frappe.get_cached_value`, with no permission check.

Fix criteria: The currency lookup must run only after the party doctype and record have been validated and permission-checked as above. Verify: an unsupported or unreadable `party_type`/`party` never puts a value from that record in the report's columns or currency.

## Evidence

**https://github.com/cx-benchmark/erpnext**

- [`erpnext/accounts/report/general_ledger/general_ledger.py:99-105`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/report/general_ledger/general_ledger.py#L99-L105)
- [`erpnext/accounts/report/general_ledger/general_ledger.py:45-50`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/report/general_ledger/general_ledger.py#L45-L50)
- [`erpnext/accounts/report/general_ledger/general_ledger.js:63-67`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/report/general_ledger/general_ledger.js#L63-L67)
- [`erpnext/accounts/report/general_ledger/general_ledger.json:17-40`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/report/general_ledger/general_ledger.json#L17-L40)
- [`erpnext/setup/doctype/employee/employee.json:890-897`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/setup/doctype/employee/employee.json#L890-L897)
- [`erpnext/setup/doctype/company/company.py:353`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/setup/doctype/company/company.py#L353)
- [`erpnext/accounts/report/general_ledger/general_ledger.py:127-140`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/report/general_ledger/general_ledger.py#L127-L140)

