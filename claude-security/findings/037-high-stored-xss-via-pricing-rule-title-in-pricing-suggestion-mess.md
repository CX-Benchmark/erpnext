# Stored XSS via Pricing Rule title in pricing suggestion message

| Field | Value |
|---|---|
| ID | `find_01EYwhAzLEE6es4gYSF3Hibr` |
| Severity | **High** |
| Status | open |
| CWE | CWE-79 — Cross-site scripting |
| Created | 2026-10-27T22:32:06.482206Z |
| Claude Security | https://claude.ai/security/findings/find_01EYwhAzLEE6es4gYSF3Hibr |

## Description

A user who can create Pricing Rules can run script in the browser of other desk users, such as a System Manager or Accounts User. The script acts with the victim's session. The attacker needs a role that can write Pricing Rules, such as Sales Manager, Purchase Manager or Accounts Manager. The function `validate_quantity_and_amount_for_suggestion` puts the rule's free-text `title` into a `frappe.msgprint()` message without `escape_html`.

```mermaid
flowchart TD
  n1["Attacker with a Pricing Rule role"]
  n2["Pricing Rule title field"]
  n3["validate_quantity_and_amount_for_suggestion"]
  n4["Victim's desk session"]
  n5["escape_html on title"]
  n6["Other desk user adding items"]
  n1 -->|"saves markup as title"| n2
  n2 -->|"read without escaping"| n3
  n6 -->|"triggers the suggestion"| n3
  n3 -->|"message runs script"| n4
  n5 -->|"not applied"| n3
  classDef actor stroke:#2563eb,stroke-width:2px
  classDef vulnerable_code stroke:#dc2626,stroke-width:2px
  classDef existing_control stroke:#16a34a,stroke-width:2px
  classDef missing_control stroke:#dc2626,stroke-width:2px,stroke-dasharray:5 5
  classDef asset stroke:#9333ea,stroke-width:2px
  classDef component stroke:#6b7280,stroke-width:1px
  class n1 actor
  class n2 component
  class n3 vulnerable_code
  class n4 asset
  class n5 missing_control
  class n6 actor
```

1. **attacker with a Pricing Rule role** saves a Pricing Rule whose `title` holds HTML. `title` is a free-text `Data` field, and the doctype uses a naming series, so Frappe's name check that forbids `<` and `>` never applies to it. ([`erpnext/accounts/doctype/pricing_rule/pricing_rule.json:107-112`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/doctype/pricing_rule/pricing_rule.json#L107-L112))
2. **attacker** sets the rule to match every transaction and to fail its quantity check. The rule leaves company and party blank, sets `apply_on` to the root Item Group, uses a very high `min_qty` and sets `threshold_percentage = 100`, so the suggestion message fires on every item fetch. ([`erpnext/accounts/doctype/pricing_rule/utils.py:312-381`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/doctype/pricing_rule/utils.py#L312-L381))
3. **another desk user** adds an item to a sales or purchase document, or saves one. The form calls `get_item_details`, which looks up pricing rules for each item. The same lookup runs again on save, and the rule's permissions play no part in it. ([`erpnext/stock/get_item_details.py:195-196`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/stock/get_item_details.py#L195-L196))
4. **the function `validate_quantity_and_amount_for_suggestion`** builds the suggestion message with `bold(args.title)` and sends it with `frappe.msgprint(msg)`. `args` is a raw Pricing Rule row and nothing escapes `title`. Frappe's `frappe.bold` only wraps the text in a tag. ([`erpnext/accounts/doctype/pricing_rule/utils.py:383-396`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/doctype/pricing_rule/utils.py#L383-L396))
5. **the victim's browser** renders the message as HTML and runs the script from the title. The form call has no `silent` flag, so the desk shows the server message to whoever is editing the document. The script runs on the ERPNext origin with the victim's session and CSRF token. ([`erpnext/public/js/controllers/transaction.js:823-835`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/controllers/transaction.js#L823-L835))

## Assessment

The attacker is a desk user with a role that can create or write Pricing Rules: Accounts Manager, Sales Manager, Purchase Manager, Website Manager or System Manager. The victim is any other user who adds an item to a Quotation, Sales Order, Delivery Note, Sales or POS Invoice, Purchase Order, Purchase Receipt or Purchase Invoice, or who saves one. The attacker needs no further action after saving the rule. The report assumes Frappe `>=17.0.0-dev,<18`, which is not in the checkout. It assumes desk `msgprint` inserts the message as HTML. It assumes the save-time `sanitize_html` returns a value unchanged if it parses as JSON, such as a double-quoted string like `"<img src=x onerror=...>"`. It also assumes `sanitize_html` leaves unchanged a value in which `html.parser` finds no complete element, such as an unterminated `<img src=x onerror=... //`. The closing tag from `frappe.bold` then completes that value in the browser. For Website Manager the gain may be small, because Frappe website scripting (not in the checkout) may already give that role same-origin script.

Impact: The attacker's script runs as the victim and can read anything the victim can read. It can also act as the victim: create or submit invoices, payments or journal entries as an accounts user, or create users and assign roles as a System Manager. This lifts a sales or purchase manager up to any role that adds items to transactions. Nothing in the code limits what the script can call.

## Recommendation

`validate_quantity_and_amount_for_suggestion` in `pricing_rule/utils.py` puts the user-written Pricing Rule `title` into an HTML message through `frappe.bold` and `frappe.msgprint` without escaping it. Markup stored in the title therefore runs in the browser of the user who receives the message.

Fix criteria: The title, like any free-text rule field, is HTML-escaped before it goes into the suggestion message. To verify, give a Pricing Rule the title `"<img src=x onerror=alert(1)>"` (JSON-quoted) or `<img src=x onerror=alert(1) //`. Then have another user add an item that triggers the suggestion. The dialog must show the literal text and run no script.

## Evidence

**https://github.com/cx-benchmark/erpnext**

- [`erpnext/accounts/doctype/pricing_rule/utils.py:383-396`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/doctype/pricing_rule/utils.py#L383-L396)
- [`erpnext/accounts/doctype/pricing_rule/utils.py:312-381`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/doctype/pricing_rule/utils.py#L312-L381)
- [`erpnext/accounts/doctype/pricing_rule/pricing_rule.json:107-112`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/doctype/pricing_rule/pricing_rule.json#L107-L112)
- [`erpnext/accounts/doctype/pricing_rule/pricing_rule.json:668-722`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/accounts/doctype/pricing_rule/pricing_rule.json#L668-L722)
- [`erpnext/stock/get_item_details.py:195-196`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/stock/get_item_details.py#L195-L196)
- [`erpnext/public/js/controllers/transaction.js:823-835`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/controllers/transaction.js#L823-L835)
- [`erpnext/controllers/accounts_controller.py:929`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/controllers/accounts_controller.py#L929)
- [`erpnext/support/doctype/warranty_claim/warranty_claim.py:114-122`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/support/doctype/warranty_claim/warranty_claim.py#L114-L122)

