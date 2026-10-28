# Stored XSS via CRM Note content rendered raw in Lead, Opportunity and Prospect Notes panel

| Field | Value |
|---|---|
| ID | `find_01DAEbbAjSxFzGRckqqWtwp8` |
| Severity | **High** |
| Status | open |
| CWE | CWE-79 — Cross-site scripting |
| Created | 2026-10-27T22:02:41.234085Z |
| Claude Security | https://claude.ai/security/findings/find_01DAEbbAjSxFzGRckqqWtwp8 |

## Description

A Sales User can store script in a CRM note that then runs in the browser of any colleague, Sales Manager or System Manager who opens that Lead or Opportunity. The attacker needs only write permission on the parent, and the script acts with the victim's session. The cause is `crm_notes.html:33`, which prints `CRM Note.note` without escaping, so the panel depends on Frappe's save-time filter alone.

```mermaid
flowchart TD
  n1["Sales User with write on Lead or Opportunity"]
  n2["add_note and edit_note"]
  n3["stored CRM Note.note"]
  n4["crm_notes.html line 33"]
  n5["victim's desk session"]
  n6["escaping or sanitizing at render time"]
  n7["Frappe sanitize_html"]
  n8["colleague or manager opening the form"]
  n1 -->|"sends crafted note"| n2
  n2 -->|"saves it"| n3
  n7 -->|"passes JSON-shaped or tag-less text"| n3
  n3 -->|"loaded with the form"| n4
  n8 -->|"opens form"| n4
  n4 -->|"runs attacker script"| n5
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
  class n7 existing_control
  class n8 actor
```

1. **Sales User** saves a crafted note through `add_note` or `edit_note`. The note is a JSON string literal such as `"<img src=x onerror=...>"` with its quotes, or an unterminated tag such as `<img src=x onerror=... //`. The same is possible through `/api/resource` or `frappe.client.save` on the parent. ([`erpnext/crm/utils.py:280-293`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/utils.py#L280-L293))
2. **Frappe `sanitize_html`** lets the value through unchanged. The report assumes it returns its input as is when the input parses as JSON or contains no HTML element. `CRM Note.note` is a `Text Editor` field without `ignore_xss_filter`, so this filter is the only barrier. ([`erpnext/crm/doctype/crm_note/crm_note.json:16-19`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/crm_note/crm_note.json#L16-L19))
3. **colleague or manager** opens the Lead or Opportunity form. This is routine. The form's refresh code, such as `show_notes` on Lead, renders the notes panel every time the form loads. ([`erpnext/crm/doctype/lead/lead.js:220-228`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/lead.js#L220-L228))
4. **`CRMNotes.refresh`** renders the `crm_notes` template from `frm.doc.notes` and appends it to the page. `$(notes_html).appendTo(this.notes_wrapper)` turns the stored text into live page elements. ([`erpnext/public/js/utils/crm_activities.js:115-127`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/utils/crm_activities.js#L115-L127))
5. **template `crm_notes.html`** prints the note body with `{{ notes[i].note }}`. The `{{ }}` operator does not escape, unlike `added_by`, which goes through `strip_html`. The handler therefore runs in the victim's desk session. ([`erpnext/public/js/templates/crm_notes.html:33`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/templates/crm_notes.html#L33))

## Assessment

The attacker is a logged-in Sales User, who holds create, read and write on Lead and Opportunity. They set `note` through `add_note` or `edit_note` (called as document methods), or by saving the parent through `/api/resource` or `frappe.client.save`. The attack works if Frappe's `sanitize_html` returns the value unchanged for JSON-parsable or element-less input. That is an assumption the report carries over from sibling findings, because Frappe is not in the checkout. The victim only has to open the form. A Prospect is also reached when a poisoned Lead is turned into a Prospect, because `create_prospect` in `lead.py` copies the notes. Sales User can only read Prospect, so direct writes to a Prospect need Sales Manager or System Manager. Notes are not copied to Opportunity.

Impact: The attacker's script runs as the victim and can read anything the victim can read. It can also call any whitelisted method or REST resource as the victim. If the viewer is a System Manager, it can create users and grant roles, which gives site-wide data disclosure and modification. The victim's roles set the limit. The report sees no direct effect on availability.

## Recommendation

(1) `crm_notes.html:33` inserts the stored `CRM Note.note` HTML into the form with the unescaped `{{ }}` operator. It trusts a framework save filter that leaves JSON-parsable or element-less input unchanged.

Fix criteria: Note content shown in the CRM Notes panel cannot run script. It is either passed through an allow-list HTML sanitizer at render time that does not skip JSON-shaped or element-less input, or shown as escaped text. To verify, add the notes `"<img src=x onerror=alert(1)>"` and `<img src=x onerror=alert(1)//` to a Lead through `add_note`. Then open the Lead, Opportunity and derived Prospect forms. No handler runs and no `onerror` attribute appears in the DOM.

(2) `add_note` and `edit_note` in `erpnext/crm/utils.py` store the caller's HTML with no cleanup beyond Frappe's generic sanitizer. That sanitizer skips JSON-parsable and tag-less strings.

Fix criteria: Note content stored through `add_note`, `edit_note` or a parent save is reduced to safe HTML whatever its outer shape. After the fix, no stored `CRM Note.note` contains `on*=` handlers, `<script>` or `javascript:` URLs. This holds even when the submitted value parses as JSON or has an unterminated tag.

## Evidence

**https://github.com/cx-benchmark/erpnext**

- [`erpnext/public/js/templates/crm_notes.html:33`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/templates/crm_notes.html#L33)
- [`erpnext/public/js/utils/crm_activities.js:115-127`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/utils/crm_activities.js#L115-L127)
- [`erpnext/crm/utils.py:280-293`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/utils.py#L280-L293)
- [`erpnext/crm/doctype/crm_note/crm_note.json:16-19`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/crm_note/crm_note.json#L16-L19)
- [`erpnext/crm/doctype/lead/lead.json:564-620`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/lead.json#L564-L620)
- [`erpnext/crm/doctype/opportunity/opportunity.json:677-700`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/opportunity/opportunity.json#L677-L700)
- [`erpnext/crm/doctype/lead/lead.js:220-228`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/lead.js#L220-L228)
- [`erpnext/crm/doctype/lead/test_lead.py:191-206`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/test_lead.py#L191-L206)
- [`erpnext/crm/doctype/lead/lead.py:317`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/lead.py#L317)

