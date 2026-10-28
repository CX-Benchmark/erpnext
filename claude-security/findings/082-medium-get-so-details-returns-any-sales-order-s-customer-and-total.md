# get_so_details returns any Sales Order's customer and total with only a doctype-level check

| Field | Value |
|---|---|
| ID | `find_01WSbzdHHTKgd1SafTcQUQgJ` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-639 — Insecure direct object reference |
| Created | 2026-10-27T21:21:08.346988Z |
| Claude Security | https://claude.ai/security/findings/find_01WSbzdHHTKgd1SafTcQUQgJ |

## Description

A logged-in user who can read Sales Orders by role can see the customer, order date and grand total of Sales Orders they should not see. This includes orders from other companies, customers or territories that their User Permissions exclude. The whitelisted `get_so_details` only checks Sales Order read permission at doctype level, then reads the record with `frappe.db.get_value`, which applies no User Permissions.

1. **attacker** calls the whitelisted endpoint with a Sales Order name. The attacker is a desk user with role-level Sales Order read and User Permissions that limit them to one company, customer or territory. They send a request to `/api/method/erpnext.manufacturing.doctype.production_plan.mapper.get_so_details?sales_order=SAL-ORD-2025-00042`. ([`erpnext/manufacturing/doctype/production_plan/production_plan.js:1028-1037`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/manufacturing/doctype/production_plan/production_plan.js#L1028-L1037))
2. **the endpoint `get_so_details`** checks only doctype-level read permission. `frappe.has_permission("Sales Order", "read", throw=True)` is called with no `doc`. It checks the role and ignores User Permissions and the specific record, so the attacker passes. ([`erpnext/manufacturing/doctype/production_plan/mapper.py:10-16`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/manufacturing/doctype/production_plan/mapper.py#L10-L16))
3. **the endpoint `get_so_details`** reads the requested order with `frappe.db.get_value`. This call applies no permission filtering. It fetches `transaction_date`, `customer` and `grand_total` for whatever name the caller gave. ([`erpnext/manufacturing/doctype/production_plan/mapper.py:10-16`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/manufacturing/doctype/production_plan/mapper.py#L10-L16))
4. **attacker** receives the values and repeats with the next name. The names follow the sequential `SAL-ORD-.YYYY.-` series, so the attacker can walk through them one by one.

## Assessment

The attacker is an authenticated desk user who holds role-level Sales Order read. The roles are Sales User, Sales Manager, Maintenance User, Accounts User and Stock User. In the report's example, User Permissions limit the user to their own company, customer or territory. The attacker needs no user interaction. The method can be reached at the `mapper.py` path or at the re-exported path `erpnext.manufacturing.doctype.production_plan.production_plan.get_so_details`, which the Production Plan form uses.

Impact: The attacker learns the customer, order date and grand total of any Sales Order, whatever its company, customer or docstatus. Only these three fields are exposed. Line items and addresses are not, and nothing can be modified. This breaks the cross-company and User Permission isolation.

## Recommendation

`get_so_details` authorises at doctype level and reads with `frappe.db.get_value`, so User Permissions on Sales Order are not applied to the requested record.

Fix criteria: The endpoint returns data only for Sales Orders the caller can read at record level, including User Permissions and company restrictions. Call it as a user scoped to company A with the name of a company-B Sales Order. The call must fail with a permission error and must not return the customer or total.

## Evidence

**https://github.com/cx-benchmark/erpnext**

- [`erpnext/manufacturing/doctype/production_plan/mapper.py:10-16`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/manufacturing/doctype/production_plan/mapper.py#L10-L16)
- [`erpnext/manufacturing/doctype/production_plan/production_plan.py:14-17`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/manufacturing/doctype/production_plan/production_plan.py#L14-L17)
- [`erpnext/manufacturing/doctype/production_plan/production_plan.js:1028-1037`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/manufacturing/doctype/production_plan/production_plan.js#L1028-L1037)
- [`erpnext/selling/doctype/sales_order/sales_order.json:1837-1907`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/selling/doctype/sales_order/sales_order.json#L1837-L1907)
- [`erpnext/manufacturing/doctype/master_production_schedule/master_production_schedule.py:566-574`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/manufacturing/doctype/master_production_schedule/master_production_schedule.py#L566-L574)

