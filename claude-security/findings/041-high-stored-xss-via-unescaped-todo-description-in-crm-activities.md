# Stored XSS via unescaped ToDo description in CRM Activities panel

| Field | Value |
|---|---|
| ID | `find_01FdtYWJSEDzGdotgxC9tE1J` |
| Severity | **High** |
| Status | open |
| CWE | CWE-79 — Cross-site scripting |
| Created | 2026-10-27T22:03:40.023309Z |
| Claude Security | https://claude.ai/security/findings/find_01FdtYWJSEDzGdotgxC9tE1J |

## Description

A user with Sales User access can store a script in a ToDo on a Lead, Opportunity or Prospect. It runs in the browser of any colleague who opens that record, including a Sales Manager or System Manager, and acts with that person's rights. The CRM Activities template prints each ToDo `description` raw with `{%= tasks[i].description %}` and `{%= t.description %}`, and Frappe's save-time filter is the only protection.

```mermaid
flowchart TD
  n1["Sales User attacker"]
  n2["ToDo on the Lead with markup in description"]
  n3["get_open_activities"]
  n4["crm_activities.html template"]
  n5["Sales Manager or System Manager opening the record"]
  n6["victim's desk session"]
  n7["escape_html on description"]
  n1 -->|"creates via New Task or ToDo API"| n2
  n5 -->|"opens the form"| n3
  n2 -->|"read back unchanged"| n3
  n3 -->|"returns description"| n4
  n4 -->|"script runs as the victim"| n6
  n7 -->|"not applied"| n4
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
  class n5 actor
  class n6 asset
  class n7 missing_control
```

1. **attacker with Sales User access** creates a ToDo on a Lead they can open. The New Task button or `POST /api/resource/ToDo` with `reference_type=Lead` does this, and `description` is set to a JSON string literal such as `"<img src=x onerror=...>"` (quotes included) or an unterminated `<img src=x onerror=... `. ([`erpnext/public/js/utils/crm_activities.js:67-83`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/utils/crm_activities.js#L67-L83))
2. **Frappe save filter** stores the description unchanged. The report assumes, without having Frappe's code, that `sanitize_html` returns such values as written because `json.loads` accepts them or no complete element is found.
3. **victim** opens the Lead, or the Opportunity it was converted into. `show_activities` runs from `refresh` on the form, and `link_open_tasks` moves open ToDos onto the Opportunity created from a Lead. ([`erpnext/crm/doctype/lead/lead.js:230-241`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/lead.js#L230-L241))
4. **the whitelisted method `get_open_activities`** returns every ToDo on the document with its stored `description`. It only checks that the viewer can read the document, and `get_filtered_todos` returns the text through `frappe.get_all` without encoding it. ([`erpnext/crm/utils.py:166-183`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/utils.py#L166-L183))
5. **the template `crm_activities.html`** writes the description into the HTML without escaping. `{%= tasks[i].description %}` is used for open ToDos and `{%= t.description %}` for closed ones, while the Event subject in the same template does go through `frappe.utils.escape_html`. ([`erpnext/public/js/templates/crm_activities.html:33-35`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/templates/crm_activities.html#L33-L35))
6. **`CRMActivities.refresh`** inserts the rendered string into the page with jQuery. jQuery builds the nodes in the live document, so the `onerror` handler of the image runs in the victim's desk session. ([`erpnext/public/js/utils/crm_activities.js:31-46`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/utils/crm_activities.js#L31-L46))

## Assessment

The attacker is a desk user with Sales User access who can open a Lead, Opportunity or Prospect form. They create a ToDo on it, either with the panel's New Task button or by posting to the ToDo REST API, with a description Frappe's save filter lets through. Any other user who can read the document then triggers the script by opening it, such as a colleague, a Sales Manager or a System Manager. The payload also follows the Lead into the Opportunity made from it. The report assumes three things about Frappe, which is not in the checkout. `ToDo.description` is a `Text Editor` field without `ignore_xss_filter`. `sanitize_html` leaves JSON-shaped and tag-incomplete values unchanged. Microtemplate `{%= %}` output is not escaped.

Impact: The script runs on the desk origin with the victim's session and CSRF token. It can read anything the victim can and call any whitelisted method or REST endpoint as the victim. The victim's roles set the limit. For a System Manager that includes changing users, roles and business data. The report names no direct effect on availability.

## Recommendation

`crm_activities.html` lines 34 and 93 put the stored `ToDo.description` into the page with the raw `{%= %}` operator. Only Frappe's save-time filter stands in the way, and it lets JSON-shaped and tag-incomplete values through.

Fix criteria: Every ToDo description the CRM Activities panel renders cannot inject markup or run script. It may be escaped as text or passed through a client-side HTML sanitiser that removes event handlers, scripts and dangerous URLs. A ToDo on a Lead with the description `"<img src=x onerror=alert(1)>"`, and another with `<img src=x onerror=alert(1) `, each show as inert text in the open and completed task lists. No handler runs when the Lead, or the Opportunity it converts to, is opened.

## Evidence

**https://github.com/cx-benchmark/erpnext**

- [`erpnext/public/js/templates/crm_activities.html:33-35`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/templates/crm_activities.html#L33-L35)
- [`erpnext/public/js/templates/crm_activities.html:92-94`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/templates/crm_activities.html#L92-L94)
- [`erpnext/public/js/utils/crm_activities.js:31-46`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/utils/crm_activities.js#L31-L46)
- [`erpnext/crm/utils.py:166-183`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/utils.py#L166-L183)
- [`erpnext/crm/utils.py:207-218`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/utils.py#L207-L218)
- [`erpnext/public/js/utils/crm_activities.js:67-83`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/utils/crm_activities.js#L67-L83)
- [`erpnext/crm/doctype/lead/lead.js:230-241`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/lead.js#L230-L241)
- [`erpnext/crm/doctype/lead/lead.json:564-614`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/doctype/lead/lead.json#L564-L614)
- [`erpnext/crm/utils.py:142-152`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/crm/utils.py#L142-L152)
- [`erpnext/public/js/templates/crm_activities.html:117-119`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/templates/crm_activities.html#L117-L119)
- [`erpnext/public/js/erpnext.bundle.js:35-36`](https://github.com/cx-benchmark/erpnext/blob/90e7aefca73da3c440d2e8da7472fcb67838e678/erpnext/public/js/erpnext.bundle.js#L35-L36)

