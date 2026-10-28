# Stored XSS via RFQ HTML message injected raw into Preview Email dialog

| Field | Value |
|---|---|
| ID | `find_01UBF8wjCSxChRfWke1YLyEP` |
| Severity | **High** |
| Status | open |
| CWE | CWE-79 — Cross-site scripting |
| Created | 2026-10-27T21:22:38.751875Z |
| Claude Security | https://claude.ai/security/findings/find_01UBF8wjCSxChRfWke1YLyEP |

## Description

A desk user with write access to Request for Quotation (Purchase User, Purchase Manager or Manufacturing Manager) can run script in a colleague's session when that colleague previews the RFQ e-mail. The script can do anything the victim's roles allow. The cause is that the Preview Email handler in `request_for_quotation.js` inserts HTML rendered from the unsanitized `Code` field `mfs_html` straight into the page with `$wrapper.append`.

```mermaid
flowchart TD
  n1["attacker with RFQ write"]
  n2["mfs_html Code field (use_html set)"]
  n3["get_supplier_email_preview"]
  n4["Preview Email handler in request_for_quotation.js"]
  n5["victim's desk session"]
  n6["sanitizing or sandboxing of preview HTML"]
  n7["colleague reviewing the draft"]
  n1 -->|"stores script markup"| n2
  n2 -->|"rendered with Jinja"| n3
  n3 -->|"returns HTML unchanged"| n4
  n7 -->|"clicks Preview Email"| n4
  n4 -->|"appended, script runs"| n5
  n6 -->|"not applied"| n4
  classDef actor stroke:#2563eb,stroke-width:2px
  classDef vulnerable_code stroke:#dc2626,stroke-width:2px
  classDef existing_control stroke:#16a34a,stroke-width:2px
  classDef missing_control stroke:#dc2626,stroke-width:2px,stroke-dasharray:5 5
  classDef asset stroke:#9333ea,stroke-width:2px
  classDef component stroke:#6b7280,stroke-width:1px
  class n1 actor
  class n2 component
  class n3 component
  class n4 vulnerable_code
  class n5 asset
  class n6 missing_control
  class n7 actor
```

1. **the attacker (desk user with RFQ write)** saves a draft RFQ with script markup in `mfs_html`. The attacker sets `use_html` to 1 and writes something like `<img src=x onerror=...>` or `<script>` into `mfs_html`, through the form or `/api/resource`, and adds a supplier row with an email. Both fields are permlevel 0, and Frappe's save-time XSS filter skips `Code` fields, so the markup is stored as written. ([`erpnext/buying/doctype/request_for_quotation/request_for_quotation.json:341-356`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.json#L341-L356))
2. **the victim (colleague reviewing the draft)** clicks Preview Email and picks the supplier. The `preview` button is shown on draft RFQs, so the attacker's saved draft is enough, and this is a routine review step. ([`erpnext/buying/doctype/request_for_quotation/request_for_quotation.json:262`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.json#L262))
3. **the whitelisted method `get_supplier_email_preview`** returns the rendered message to the browser. It calls `supplier_rfq_mail(..., preview=True)`, which renders `mfs_html` with Jinja and `restrict_globals=True`. The sandbox limits server-side globals but leaves the markup untouched, so the HTML string comes back unchanged. ([`erpnext/buying/doctype/request_for_quotation/request_for_quotation.py:337-351`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.py#L337-L351))
4. **the Preview Email handler in `request_for_quotation.js`** appends the returned HTML to the dialog. `dialog.fields_dict.email_preview.$wrapper.append(message.message)` inserts the string with no sanitization. jQuery 3 runs inline scripts, and handler attributes such as `onerror` fire once the markup is in the live document. ([`erpnext/buying/doctype/request_for_quotation/request_for_quotation.js:308-314`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.js#L308-L314))
5. **the attacker's script** runs in the victim's desk session. It runs on the ERPNext origin with the victim's session and `frappe.csrf_token`, so it can read and call whatever the victim's roles allow.

## Assessment

The attacker is a desk user with write access to Request for Quotation (Purchase User, Purchase Manager or Manufacturing Manager). No other setting is needed. The attacker needs a draft RFQ with `use_html` set, markup in `mfs_html` and a supplier row with an email. The victim must open Preview Email on that draft and pick the supplier. The `message_for_supplier` Text Editor field is HTML-sanitized on save, but its Jinja rendering could still emit markup, for example by building `<` with the `format` filter. The report calls this route secondary and says it was not needed for the finding. The report assumes the Frappe filter behaviour from upstream source, since that code is not in the checkout.

Impact: The attacker's script runs as the victim and can read anything the victim can read and perform any desk or API action the victim may perform. A Purchase Manager victim could have purchase documents submitted or cancelled. An Administrator or System Manager victim with RFQ read could have privileged users created. The damage is bounded by the victim's roles.

## Recommendation

The e-mail preview inserts HTML rendered from an attacker-authored `Code` field (exempt from Frappe's document XSS filter) into the desk page with `$wrapper.append`. Content from one desk user can therefore execute script in another user's session.

Fix criteria: Previewing an RFQ e-mail does not execute active content from `mfs_html` or `message_for_supplier`. The rendered HTML is either sanitized before it is returned or inserted, or isolated, for example in an iframe sandboxed without script permission. To verify, store `<img src=x onerror=alert(1)>` and `<script>alert(1)</script>` in `mfs_html` with `use_html=1`, open Preview Email as another user, and confirm nothing executes. Ordinary formatting must still render.

## Evidence

**https://github.com/cx-benchmark/erpnext**

- [`erpnext/buying/doctype/request_for_quotation/request_for_quotation.js:308-314`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.js#L308-L314)
- [`erpnext/buying/doctype/request_for_quotation/request_for_quotation.py:188-198`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.py#L188-L198)
- [`erpnext/buying/doctype/request_for_quotation/request_for_quotation.py:337-351`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.py#L337-L351)
- [`erpnext/buying/doctype/request_for_quotation/request_for_quotation.json:341-356`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.json#L341-L356)
- [`erpnext/buying/doctype/request_for_quotation/request_for_quotation.json:262`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/buying/doctype/request_for_quotation/request_for_quotation.json#L262)

