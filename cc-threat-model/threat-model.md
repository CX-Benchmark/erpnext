# ERPNext threat model (github.com/cx-benchmark/erpnext, develop)

## system

- **What it is.** ERPNext is an ERP (accounting, stock, selling, buying, manufacturing, subcontracting, projects, CRM, support, assets, quality, POS, banking) built as an app on the Frappe Framework (README.md "Under the Hood"; pyproject.toml requires frappe ">=17.0.0-dev,<18.0.0" and Python >=3.14). ERPNext has no HTTP stack of its own. Requests reach its code only through Frappe, which is out of view. Frappe provides: /api/method/<dotted.path> for @frappe.whitelist functions, run_doc_method for whitelisted Document methods, /api/resource CRUD plus list and report APIs on ERPNext DocTypes, the website router for erpnext/www and erpnext/templates/pages, web forms, print/PDF, data import, background jobs and the scheduler. Frappe's authentication, sessions, CSRF, ORM permission engine, Jinja environment and safe_eval are also out of view.
- **Server components** (erpnext/):
  - 855 @frappe.whitelist decorators in 243 non-test .py files: 687 module-level functions and 168 Document methods.
  - 536 DocType definitions, whose role permissions are the "permissions" rows in each */doctype/*/*.json.
  - Reports under */report/*: 181 Script Reports, 8 Query Reports and 6 Report Builder, by report_type in their JSON.
  - Hooks in erpnext/hooks.py: doc_events (including "*" validate hooks), scheduler_events, and the permission hooks permission_query_conditions, has_permission, has_website_permission and has_upload_permission.
  - Modules (erpnext/modules.txt, top-level dirs): accounts, stock, selling, buying, manufacturing, subcontracting, projects, crm, support, assets, quality_management, maintenance, regional (Italy e-invoice, UAE, etc.), erpnext_integrations (Plaid only), telephony (Call Log, Voice Call Settings), edi (genericode code lists), communication, utilities, setup, portal, www, templates, controllers, bulk_transaction.
  - erpnext/shopping_cart contains only empty package files (\_\_init\_\_.py). The webshop and payment-gateway callbacks are not in this repository: payment_request.py imports from the separate "payments" app behind erpnext/utilities/__init__.py payment_app_import_guard.
- **Clients.**
  - Desk JS: erpnext/public/js and per-doctype .js files, bundled as erpnext.bundle.js (hooks.py app_include_js).
  - banking/: a React/TypeScript Vite SPA for bank reconciliation and bank statement import. "yarn build" builds it into erpnext/public/banking and copies index.html to erpnext/www/banking.html (banking/package.json; pyproject [tool.bench.assets]). It is served at /banking/<path> (hooks.py website_route_rules → erpnext/www/banking.py) and calls whitelisted methods in accounts/doctype/bank_reconciliation_tool, bank_transaction, bank_account and bank_statement_import_log.
  - Portal for customers and suppliers: hooks.py website_route_rules map /orders, /invoices, /quotations, /shipments, /supplier-quotations, /purchase-orders, /purchase-invoices, /rfq, /addresses, /material-requests, /project, /tasks, /timesheets and /banking. Further pieces: standard_portal_menu_items, the web forms addresses, issues and tasks, and the list providers (14 get_list_context definitions).
- **Principals the code trusts.**
  - Administrator: check_app_permission in erpnext/__init__.py returns True for it, and setup/install.py after_install calls add_all_roles_to("Administrator").
  - System Manager: it writes the Settings singletons that drive outbound URLs, guest features and evaluated content (role lists below).
  - Role-holding System Users (Accounts, Sales, Purchase, Stock, Manufacturing, Projects, HR, Quality, Maintenance, Delivery users and managers, Auditor) and the minimal "Desk User" role. These come from the DocPerm rows.
  - Website Users holding the Customer or Supplier role: setup/install.py update_roles sets desk_access 0 on those roles.
  - Guest.
- **How a portal user maps to a party.**
  - The link is "Portal User" child rows on Customer or Supplier (controllers/website_list_for_contact.py get_parents_for_user).
  - The Customer and Supplier roles are added in three places:
    - portal/utils.py set_default_role, a User on_update hook that runs when a Contact with the user's email links to a Customer or Supplier.
    - website_list_for_contact.add_role_for_portal_user, which adds the role only when the editor has System Manager.
    - Request for Quotation send_to_supplier (buying/doctype/request_for_quotation/request_for_quotation.py, update_supplier_contact and create_user). It creates the User, Contact and Portal User row for each supplier email, with ignore_permissions.
  - portal/utils.py create_customer_or_supplier (hooks.py on_session_creation) creates a Customer or Supplier and a Contact for a Website User at login. It does this when Portal Settings.default_role is Customer or Supplier and the user holds that role.
- **Build, ship and deploy, per the repository's own files.**
  - Install: README.md sends production users to Frappe Cloud or frappe_docker, both external. Development uses bench get-app/install-app. The Python package is built by flit (pyproject).
  - .github/workflows/build-and-commit-assets.yml: on push to develop or version-*, builds JS/CSS and uploads erpnext-assets.tar.gz to the rolling prerelease "assets-<branch>" with GITHUB_TOKEN (contents: write).
  - docker-release.yml: on release, triggers the frappe_docker stable build with secrets.CI_PAT.
  - release.yml: runs semantic-release on version-13 with a Frappe Release Bot app token.
  - Translations come in from Crowdin as pull requests (crowdin-actions-download-translations.yml).
  - Deployment, per .oss-scanner/threat_model.md, a document written for a scanner: ERPNext "runs on the public Internet, often with several companies on one site and many sites on one bench".

## adversaries

Ordered by the access each needs. "Frappe out of view" means the dispatcher or permission layer in front of the ERPNext code was not read.

**A1. Unauthenticated internet user (Guest).** There are exactly 7 allow_guest methods. For each, the access is anonymous: allow_guest=True, no login check in the handler, and the Frappe dispatcher is out of view.
- erpnext/www/banking.py get_context_for_dev (POST): throws unless frappe.conf.developer_mode is set, then calls validate_desk_user. That function redirects Guest with a 403 and raises PermissionError for website users. In practice the method serves only desk users, and only in developer mode.
- erpnext/www/book_appointment/index.py get_appointment_settings, get_timezones, get_appointment_slots and create_appointment:
  - All four call handle_appointment_booking_disabled, which checks Appointment Booking Settings.enable_appointment_portal.
  - get_appointment_slots is limited by rate_limit to 60 per 60 s. create_appointment is POST-only and limited to 5 per 300 s.
  - create_appointment inserts an Appointment with ignore_permissions=True. The guest's "contact" JSON supplies name, number, skype, notes and email.
  - crm/doctype/appointment/appointment.py generate_verification_key stores sha256(frappe.generate_hash()) and emails the verification link.
- erpnext/templates/pages/search_help.py get_help_results_sections(text): for each Support Settings.search_apis row:
  - "API" rows: requests.get(api.base_url + "/" + api.query_route, data={param: text}) with no timeout argument.
  - Other rows: frappe global search(text, 0, 20, api.source_doctype), returning title, preview and route fields.
  - The rows are configured by System Manager.
- erpnext/templates/utils.py send_message (POST; rate_limit 10 per 180 s). It replaces Frappe's frappe.www.contact.send_message (hooks.py override_whitelisted_methods).
  - It returns early if Contact Us Settings.is_disabled.
  - Otherwise it calls Frappe's send_message. If CRM Settings.enable_opportunity_creation_from_contact_us is set, it then inserts a Lead, an Opportunity and a Communication with ignore_permissions=True.
  - It links the message to an existing Customer only when the session user equals the sender.

Guest-reachable web pages. The website router is out of view; the checks listed are the ones in each get_context.
- erpnext/www/book_appointment/verify/index.py: looks up an Appointment by sha256(form_dict.key). It refuses Closed or already-verified appointments, expired links and past scheduled times. It then sets status Open with save(ignore_permissions=True) and commits on a GET.
- templates/pages/partners.py: Sales Partners with show_in_website=1, fields ["*"].
- templates/pages/help.py: fetches Support Settings.forum_url with a 10 s timeout. Issues are listed only for non-Guest users, via get_list.
- www/support/index.py: published Help Articles.
- www/payment_setup_certification.py: returns data only for non-Guest users.
- Website generators BOM and Sales Partner, gated by show_in_website (manufacturing/doctype/bom/bom.py and setup/doctype/sales_partner/sales_partner.py, website.condition_field).
- templates/pages/timelog_info.py: frappe.get_doc("Time Log", form_dict.timelog) with no check. No DocType "Time Log" is defined in this repository.
- www/banking.py get_context: validate_desk_user rejects Guest and website users.

**A2. Portal user: a Website User with the Customer or Supplier role.** A portal user must see only their own party's documents. Self sign-up depends on a Frappe setting (out of view).
- Detail pages:
  - /<orders|invoices|quotations|shipments|supplier-quotations|purchase-orders|purchase-invoices>/<name> → templates/pages/order.py get_context. It loads the doc named by form_dict.doctype and form_dict.name, then requires doc.has_permission("read") or frappe.has_website_permission(doc). It reads the Payment Request and print-format Property Setter before that check.
  - /material-requests/<name> → templates/pages/material_request_info.py, with the same check.
  - /rfq/<name> → templates/pages/rfq.py: requires docstatus 1, and unauthorized_user requires a Request for Quotation Supplier row for the user's supplier.
  - /project → templates/pages/projects.py validate_and_get_project_user: website users go through has_website_permission, everyone else through check_permission.
  - task_info.py: task.check_permission().
- has_website_permission hooks (hooks.py):
  - Sales Order, Quotation, Sales Invoice, Supplier Quotation, Purchase Order, Purchase Invoice, Material Request, Delivery Note, Timesheet and Project use controllers/website_list_for_contact.py has_website_permission. It requires the Customer or Supplier role, then matches the doc's customer/party_name (Quotation also needs quotation_to=Customer), or supplier/suppliers, against the user's Portal User parents.
  - Issue uses support/doctype/issue/issue.py has_website_permission: raised_by == user grants any ptype; otherwise read and print go through the party check.
- Lists:
  - website_list_for_contact.get_transaction_list filters by the user's parties, then lists with ignore_permissions=True. get_portal_row cuts each row down to PORTAL_ROW_FIELDS.
  - A user without the portal roles who can read the doctype and Customer gets customers = suppliers = all readable Customer names (get_customers_suppliers).
  - Other list providers: issue.get_issue_list, project.get_project_list and timesheet.get_timesheets_list. RFQ uses rfq_transaction_list.
- Web forms (the engine is Frappe's, out of view):
  - utilities/web_form/addresses: login_required, apply_document_permissions 1.
  - support/web_form/issues: login_required, allow_edit and allow_delete, apply_document_permissions 0.
  - projects/web_form/tasks: login_required, allow_delete.
- Portal write and read methods. Any logged-in user can call them; the check is in the body.
  - buying/doctype/request_for_quotation/mapper.py create_supplier_quotation (POST):
    - The session user must be a Portal User of doc.supplier.
    - get_quotable_rfq requires a submitted RFQ that lists that supplier.
    - Each row must be an RFQ row; qty and rate come from the caller.
    - The quotation is saved with flags.ignore_permissions.
  - buying/doctype/purchase_order/mapper.py make_purchase_invoice_from_portal: maps the PO with ignore_permissions, then requires a Portal User match on doc.supplier, then saves.
  - templates/pages/projects.py get_task_html and get_timesheet_html: both call validate_and_get_project_user.
  - accounts/doctype/payment_request/payment_request.py make_payment_request (POST): requires has_permission on Payment Request "create" and "read" on args.dt/args.dn.
  - request_for_quotation.py get_pdf: relies on Frappe's download_pdf ("permissions get checked in download_pdf").
- .oss-scanner/threat_model.md says that "/api/method/... works for any logged-in user" unless a method checks for a role. By that account a Website User also reaches the A3 surface. This is Frappe behaviour, out of view.

**A3. Any logged-in System User, down to the "Desk User" role.** This actor reaches the 848 non-guest whitelisted functions and methods, each gated only by its body or its callees. It also reaches Frappe's generic CRUD and report APIs, gated by the DocPerm JSON:
- Desk User: select on Company, Item, UOM and Item Group; read on Service Level Agreement and the Quality Action, Feedback, Goal, Review, Meeting and Procedure doctypes.
- Desk User: create, read and write on Voice Call Settings (narrowed by voice_call_settings.has_permission and its query conditions to the user's own record); create, write and delete on Video with if_owner.
- Desk User: permlevel-1 read on Project and Lead.
- Role "All": permlevel-1 read on Sales Invoice, POS Invoice and Request for Quotation.

Enforcement idioms. Each appears at more than one call site:
- Calls in the body:
  - frappe.has_permission(..., throw=True) or doc.check_permission(ptype). Examples:
    - All six module-level methods in erpnext_integrations/doctype/plaid_settings/plaid_settings.py check Plaid Settings.
    - bank_statement_import_log.py: get_statement_details, update_pdf_tables, reextract_pdf_table and set_pdf_table_header.
    - bank_statement_import.py: convert_mt940_to_csv and form_start_import.
    - telephony/doctype/call_log/call_log.py add_call_summary_and_call_type: read, plus write unless the caller is the agent.
  - frappe.only_for, at 13 call sites. Example: accounts/doctype/cheque_print_template create_or_update_cheque_print_format requires System Manager.
- erpnext/__init__.py helpers:
  - require_permission (frappe.has_permission on the record), require_user_permission (has_user_permission) and require_party_permission (Party Type exists, then has_permission read or select).
  - 27 call sites in 10 files: asset_capitalization, tax_rule, bank_reconciliation_tool, accounts/services/taxes, serial_and_batch_bundle, quick_stock_balance, stock_entry, stock/get_item_details, stock/utils and bom_update_tool.
- controllers/queries.py: all 26 link-search methods use @frappe.validate_and_sanitize_search_inputs. They query through frappe.qb.get_query(..., ignore_permissions=False), frappe.get_list or explicit has_permission calls.
- Private helpers with an ignore_permissions flag:
  - accounts/party.py get_party_details → _get_party_details checks frappe.has_permission(party_type, ptype, party) unless ignore_permissions is set.
  - selling/page/point_of_sale/point_of_sale.py check_pos_profile_access and check_pos_item_access check the POS Profile record permission and the item group.
- Exceptions:
  - About 230 module-level functions have no permission call in their own body. This was found by a mechanical scan, not by reading each one. Many delegate to helpers or to Frappe's Document.insert/save/delete or get_mapped_doc (out of view). Coverage per function: not verified.
  - Named functions whose body reads or writes with no check of its own:
    - request_for_quotation.py send_supplier_emails: get_doc, then send_to_supplier, which creates Users, Contacts and Portal Users with ignore_permissions. It is gated only by check_portal_enabled.
    - controllers/sales_and_purchase_return.py is_invoice_returnable: frappe.db reads.
    - serial_and_batch_bundle.py is_duplicate_serial_no.
    - process_payment_reconciliation.py is_any_doc_running.
    - chart_of_accounts.py validate_bank_account and build_tree_from_json.
    - Relying on doc.save(): bank_statement_import_log.py update_column_mapping and set_header_index, bank_reconciliation_tool.py update_bank_transaction, set_multiple_status in task.py and opportunity.py, work_order.py set_work_order_ops.
    - Relying on doc.delete(): inventory_dimension.py delete_dimension.
    - The tree add_node methods (task, location, company, department, warehouse, quality_procedure) and accounts/utils.py add_cc: frappe.get_doc(form_dict).insert().
- Document methods (168) are reached through Frappe's run_doc_method, whose permission check is out of view. Some re-check in the body, e.g. issue.py split_issue calls check_permission("write").

Reports:
- Frappe runs execute(filters) for users holding a role listed in the report's JSON (out of view).
- Outside tests and patches there are 24 frappe.db.sql calls; the rest use frappe.qb. In accounts/report/general_ledger/general_ledger.py get_gl_entries, filter values are bound as %(name)s parameters, while column lists and the order-by clause are f-string fragments.
- Company checks: trial_balance.py validate_company_permission and stock_ledger_entries_of_cancelled_vouchers.py.
- DuckDB snapshot reports (general_ledger.execute_snapshot_report, plus the duckdb paths in profit_and_loss_statement and trial_balance) read a copy that cannot apply permission conditions. execute_snapshot_report falls back to the normal path when accounts/report/utils.py has_gl_entry_restrictions() (build_match_conditions on GL Entry) is non-empty.

File parsers reachable by role holders:
- Bank Statement Import Log (bank_statement_import_log.py):
  - validate requires Bank Transaction write, create and submit.
  - Formats: CSV, XLSX and XLS through frappe csvutils/xlsxutils, and PDF through pdfplumber/pypdf using the decrypted Bank Account.statement_password.
- MT940 (bank_statement_import.py convert_mt940_to_csv, using mt-940).
- Bank transaction CSV/XLSX upload (bank_transaction_upload.py).
- genericode XML (edi/doctype/code_list/code_list_import.py import_genericode and process_genericode_import). Remote URLs are refused by is_local_file_url.
- Italian e-invoice ZIP of XML files (regional/doctype/import_supplier_invoice, BeautifulSoup "xml").
- Rename Tool CSV (utilities/doctype/rename_tool upload → validate_access).
- Chart of Accounts importer.
- Data import providers for Customer and Supplier (hooks.py data_import_providers → utilities/party_import_provider.py).

**A4. Users in another company, or restricted by User Permissions.** These are the "tenants" inside one site. Sites on one bench are separated by Frappe (out of view).
- Frappe User Permissions on Company, Warehouse and similar links: out of view.
- ERPNext Company Restriction (stock/doctype/company_restriction/company_restriction.py):
  - hooks.py registers permission_query_conditions and has_permission for Item, Customer and Supplier, and "*" entries (get_inherited_permission_query_conditions and has_inherited_permission) for every doctype that links to those masters.
  - validate_transaction_company runs on every doc validate ("*"), except COMPANY_RESTRICTION_EXEMPT_DOCTYPES.
  - validate_allowed_companies runs on Item, Customer and Supplier.
  - The restriction applies only when the user has Company User Permissions (get_allowed_companies returns None otherwise) and the master has restrict_to_companies set.
- startup/boot.py boot_session sends name, currency, cost center, default accounts and similar fields for all Companies (frappe.get_all) to every desk session.

**A5. Role holders who author expressions or templates the server evaluates.**
- frappe.safe_eval (Frappe sandbox, out of view) runs on:
  - Pricing Rule.condition (accounts/doctype/pricing_rule/utils.py). Writers: Accounts, Purchase, Sales, System and Website Manager.
  - Service Level Agreement.condition. Writer: System Manager.
  - Quality Inspection reading acceptance_formula (stock/doctype/quality_inspection/quality_inspection.py). Quality Inspection Template writers include Stock User and Manufacturing User.
  - Bank Transaction Rule formulas (accounts/doctype/bank_transaction_rule). Writers include Accounts User. The banking SPA also evaluates them client-side with safe-expr-eval.
  - Supplier Scorecard Criteria (System Manager), Financial Report Template formulas (Accounts Manager) and Inventory Dimension conditions (Stock Manager).
- frappe.render_template (Frappe Jinja, out of view):
  - With restrict_globals=True: Terms and Conditions (setup/doctype/terms_and_conditions; writers Accounts Manager, HR Manager, Sales Master Manager, System Manager), Contract Template, Email Template (utilities/email_template.py), Email Campaign, Dunning letter texts, Process Statement of Accounts pdf_name/subject/body (writers Accounts User and Accounts Manager), Payment Request message, RFQ supplier email, and the Address template.
  - Without restrict_globals: Letter Head content and footer in process_statement_of_accounts.py (nosemgrep frappe-ssti), and Parcel Service.url_reference in erpnext_integrations/utils.py get_tracking_url. get_tracking_url has no callers, and no "Parcel Service" DocType is defined here.

**A6. Malicious third-party data or remote peer.**
- Statement, e-invoice and genericode files authored outside the site and uploaded by A3/A5 users.
- Plaid transaction data, synced on the scheduler (plaid_settings.sync_transactions → new_bank_transaction insert and submit).
- Responses from admin-configured URLs:
  - Support Settings: search_apis and forum_url.
  - Currency Exchange Settings.api_endpoint (setup/utils.py get_exchange_rate). Only system users trigger the remote fetch (is_system_user check).
- The YouTube API (utilities/doctype/video) and googlemaps (stock/doctype/delivery_trip).
- ERPNext registers no inbound webhook at this commit. erpnext_integrations/utils.py validate_webhooks_request and get_webhook_address have no callers, and the package they name (erpnext.erpnext_integrations.connectors) does not exist. Payment-gateway callbacks are in the payments app (out of view).

**A7. CI and supply chain.**
- Workflows triggered by pull_request_target:
  - cancel-closed-batch-runs.yml: actions: write, gh api only, no checkout.
  - labels.yml: actions/labeler@v3 and github-script, no checkout of PR code.
  - review-translation-changes.yaml: alyf-de/po-review-action pinned by SHA.
- post-review.yml: workflow_dispatch using secrets.RELEASE_TOKEN; jq validates the review JSON before posting as frappe-pr-bot.
- Crowdin translations arrive as pull requests. Most actions are pinned by tag; crowdin and po-review are pinned by SHA.

**Entry points left out.** About 800 whitelisted functions and Document methods are not listed one by one. They are all registered by @frappe.whitelist in erpnext/**/*.py. Decorators per module: accounts 236, stock 167, manufacturing 109, selling 69, controllers 50, assets 40, setup 37, buying 31, crm 26, projects 23, subcontracting 19, support 10, utilities 7, erpnext_integrations 7, maintenance 6, www 5, templates 4, regional 3, quality_management 3, edi 2, telephony 1. Also left out are the generic Frappe APIs on the 536 DocTypes, governed by each DocType JSON's "permissions". Malicious admin-level configuration by System Manager or Administrator is the lowest priority, as in the threat model on file and .oss-scanner/threat_model.md.

## assets

1. **Financial and stock ledger integrity.**
   - GL Entry, Stock Ledger Entry and Payment Ledger Entry are submittable, and every role's DocPerm on them is read-only. GL Entry, for example, gives read to Accounts User, Accounts Manager and Auditor, and no create or write. Controllers write these entries.
   - On cancellation, reversal entries are created. hooks.py auto_cancel_exempted_doctypes comments: "Reverse ledger entries are created instead to ensure ledger immutability".
   - Period lock: hooks.py period_closing_doctypes → accounts/doctype/accounting_period validate_accounting_period_on_doc_save.
   - Approval limits: setup/doctype/authorization_control, which uses raw SQL.
   - Also at stake: submitted and cancelled document state, bank reconciliation state (Bank Transaction, bank_reconciliation_tool.py), and stock valuation reposting.
2. **Confidential business data.** Customers, suppliers, pricing and margins, bank accounts, employees, contracts and call logs.
   - Contract: crm/doctype/contract/contract.py has_permission and get_permission_query_conditions through ContractPartyAccess.
   - Call Log: call_log.has_permission returns True when call_received_by is set, when employee_user_id is the user, or when the user reads through a role other than Employee (has_unrestricted_access). get_permission_query_conditions applies the same rule.
   - Asset Activity: query conditions are inherited from Asset.
   - Portal list rows are cut down by get_portal_row, whose docstring says the full document "would expose cost and margin fields".
3. **Company, record and party separation.** Enforced by company_restriction.py, Frappe User Permissions (out of view), Portal User matching in website_list_for_contact.py, and the erpnext/__init__.py require_* helpers.
4. **Secrets stored in DocTypes.**
   - Plaid Settings.plaid_secret: a Password field, read through get_password in plaid_connector.py.
   - Bank.plaid_access_token: a hidden Data field at permlevel 0. Bank gives read and write to System Manager and select to Accounts User and Accounts Manager.
   - Bank Account.statement_password: a Password field, read with get_decrypted_password in bank_statement_import_log.py.
   - Video Settings.api_key: a Data field (System Manager).
   - Appointment.verification_token: stores sha256 of the emailed key.
   - No other Password fields are defined in this repository. Site, database and mail credentials live in Frappe's site_config (out of view).
5. **Server capabilities an attacker could borrow.**
   - Outbound HTTP: search_help.py, help.py, setup/utils.py, code_list_import.fetch_genericode_from_url (backend-only), Plaid, YouTube and googlemaps.
   - Email: 17 frappe.sendmail or send-email call sites, including the guest-triggered appointment verification mail and RFQ supplier welcome mails.
   - User and party creation: RFQ suppliers and portal login.
   - Evaluation of Jinja templates and safe_eval expressions (A5).
6. **Availability.** Guest booking and contact endpoints are rate-limited (above). get_help_results_sections makes outbound calls with no timeout. Heavy work runs on queues: repost_item_valuation, bom_update_log, bulk_transaction, process_payment_reconciliation.
7. **Integrity of what is shipped.** The GitHub release and prerelease asset tarball, the frappe_docker build trigger, translations, and the PyPI/flit package metadata.

**Trust boundaries and where they are enforced:**
- Guest ↔ site: the allow_guest list in A1 and the settings gates inside each handler.
- Website user ↔ desk:
  - erpnext/__init__.py check_app_permission controls the apps screen.
  - www/banking.py validate_desk_user.
  - desk_access 0 on the Customer and Supplier roles (setup/install.py update_roles).
  - The API is not blocked by role, per .oss-scanner/threat_model.md (Frappe, out of view).
- Party ↔ party: website_list_for_contact.has_website_permission, get_customers_suppliers and get_parents_for_user, and issue.has_website_permission.
- Role ↔ role and record ↔ record: DocPerm JSON enforced by Frappe, plus the in-body checks listed under A3.
- Company ↔ company: company_restriction.py and the report-level validate_company_permission.
- Server ↔ evaluated content: Frappe's safe_eval and Jinja sandbox (out of view). In the Frappe docs, restrict_globals narrows the template context; not verified here.
- Desk browser ↔ stored data:
  - Desk JS and the banking SPA render server data.
  - banking/src/components/ui/markdown.tsx renders markdown with rehype-raw, which passes raw HTML through. Its callers are ui/error-banner.tsx (server messages), BankReconciliation/BankClearanceSummary.tsx, IncorrectlyClearedEntries.tsx and RecordPaymentModalContent.tsx.
  - www/banking.py get_boot strips <script> tags from the boot JSON embedded in banking.html.

## out-of-scope
What follows reports the repositories' own statements and exempts nothing from the audit.


- **SECURITY.md:** "To report a security issue, please email security@frappe.io or go through the information mentioned [at] frappe.io/security". It states no scope.
- **README.md:** the frappe_docker pwd.yml setup is a "Disposable demo only… intended for quick evaluation. Expect to throw the environment away", and comes with a fixed default Administrator login that the README prints. For "production deployments, custom configurations" it points to the full documentation, Frappe Cloud or frappe_docker. The bench install script generates new passwords and saves them to ~/frappe_passwords.txt.
- **.oss-scanner/threat_model.md.** It was written to instruct a scanner, so it is cited as evidence and decides nothing here.
  - It puts out of scope "the Frappe Framework itself (enrolled separately as frappe), node_modules/, generated files, test fixtures, and demo data".
  - It treats "System Manager, and managers such as Accounts Manager: trusted to configure their area" and "Administrator and anyone with shell access to the bench: fully trusted".
  - Its "Known non-findings" list:
    - Code guarded by a check that actually covers the actor and the record.
    - ignore_permissions=True reachable only from a scheduled job, patch, install script or test.
    - What only Administrator, System Manager or the relevant manager can reach, when the impact does not exceed that role.
    - "Accounting results that depend on site configuration".
    - "Behaviour that only exists because of a weakened development setting (ignore_csrf, developer_mode, allow_tests, server_script_enabled)".
- **The threat model on file:** Frappe itself (auth, sessions, ORM, permission engine, REST) is out of view; "Malicious admin-level config is lower priority (System Manager is trusted)".
- **.guard/config.toml and .greptile/config.json** are review-bot rules and decide nothing here. They say "Security and permission holes are an exception: report them even when the trigger is rare". They also say ERPNext must behave the same on MariaDB and PostgreSQL.
- **Required of whoever deploys, per the code:**
  - developer_mode must be off; www/banking.py get_context_for_dev is gated only by it.
  - Several guest features are opt-in settings: Appointment Booking Settings.enable_appointment_portal, CRM Settings.enable_opportunity_creation_from_contact_us (with Contact Us Settings.is_disabled), Support Settings.search_apis and forum, and the Portal Settings menu items.
  - Payment gateways require the separate payments app.
  - The shipped default values of these settings were not verified.

## production

- **erpnext/** (read: entry points, hooks, permission code, portal, guest, integrations, parsers; the bodies of about 800 authenticated whitelisted functions were scanned mechanically, not read one by one). Production: the Frappe app that bench get-app/install-app installs (README). Inside it:
  - Module directories (accounts … utilities, controllers, setup, startup, portal, www, templates, edi, regional, telephony, erpnext_integrations, bulk_transaction, communication, config, domains, dock, desktop_icon, workspace_sidebar, report_center, hooks.py, modules.txt): production server code and DocType, report and print JSON.
  - erpnext/patches/ and patches.txt: production. Migrations run by bench migrate; CI exercises them in patch.yml.
  - erpnext/public/: production. JS, CSS, icons and images served at /assets/erpnext, built by build-and-commit-assets.yml.
  - erpnext/locale/: production. Shipped translations (.po/.pot) synced with Crowdin.
  - erpnext/gettext/: tooling. Translation string extractors wired in babel_extractors.csv.
  - erpnext/commands/: production but empty (commands = []).
  - erpnext/setup/demo.py and setup/demo_data/: production. Demo data is created on request; clear_demo_data is whitelisted. codecov.yml ignores "erpnext/demo".
  - erpnext/deprecation_dumpster.py: production. Deprecated shims, with no whitelisted functions.
  - erpnext/tests/ and every */test_*.py: tests. Run by server-tests-mariadb.yml, server-tests-postgres.yml and run-individual-tests.yml with allow_tests; they ship in the package but are not executed in production.
  - erpnext/change_log/: documentation (release notes).
- **banking/** (read: package.json, vite.config.ts, proxyOptions.ts, index.html, src/ listing, markdown.tsx). Production client source: built into erpnext/public/banking and erpnext/www/banking.html. The build output is gitignored (.gitignore), so it is built at install or build time per pyproject [tool.bench.assets]. Whether build-and-commit-assets.yml includes it: not verified. vite dev server (host 0.0.0.0, port 8080) and proxyOptions.ts are development tooling.
- **.github/** (read): CI tooling.
  - workflows/ and helper/ (install.sh, start-db.sh, postgres_compat.py, dependency_audit.sh, translation scripts).
  - Credentials used: GITHUB_TOKEN, a Frappe Release Bot GitHub App token (FRAPPE_BOT_PRIVATE_KEY), CI_PAT, RELEASE_TOKEN, CROWDIN_PERSONAL_TOKEN and GHCR credentials. These are repository secrets; their values are not in the repository.
  - Runner labels erpnext-arc-light and erpnext-arc-patch, which are not GitHub-hosted labels.
- **.oss-scanner/** (read): scanner harness, not shipped. Its Dockerfile builds a test bench with fixed demo passwords, and it includes threat_model.md.
- **semgrep/** (read): CI lint rules for test correctness (pr-checks.yml).
- **.greptile/, .guard/, .coderabbit.yml, .mergify.yml, sider.yml, codecov.yml, commitlint.config.js, .pre-commit-config.yaml, .eslintrc, .flake8, .editorconfig, .git-blame-ignore-revs, .releaserc, .semgrepignore (empty), crowdin.yml, babel_extractors.csv:** tooling and configuration.
- **package.json and yarn.lock:** production. JS dependencies bundled into the assets: occt-import-js, onscan.js and three. package.json "postinstall" also installs banking/.
- **pyproject.toml:** production packaging (flit_core) and dependency pins.
- **README.md, SECURITY.md, CODE_OF_CONDUCT.md, TRADEMARK_POLICY.md, attributions.md, sponsors.md, license.txt (GPL-3.0), CODEOWNERS:** documentation.

## facts

- **Security policy:** SECURITY.md is present: email security@frappe.io or follow frappe.io/security.
- **Template engine and escaping:**
  - Templating is Jinja through Frappe: frappe.render_template, the website router, web forms and print formats (all out of view).
  - No autoescape setting is made in this repository. Templates escape explicitly: 76 uses of "| e" or "| escape" in .html files, and no "| safe". Python code calls escape_html 80 times.
  - restrict_globals=True is passed on the user-authored template sites listed under A5.
  - React in banking/ escapes by default; markdown.tsx with rehype-raw is the exception.
- **Serialization formats and loaders:**
  - JSON throughout (frappe.parse_json, json.loads, DocType JSON fields such as pdf_tables).
  - No pickle, yaml, marshal or shelve loaders exist in erpnext/ (grep).
  - frappe.safe_eval also parses stored dict keys in stock/stock_ledger.py (lines 745 and 961).
  - XML:
    - edi code_list_import.parse_genericode_content uses lxml XMLParser(resolve_entities=False, load_dtd=False, no_network=True); common_code.py uses it too.
    - regional/doctype/import_supplier_invoice uses BeautifulSoup(content, "xml"); its parser options are not set in ERPNext (not verified).
  - PDF: pdfplumber and pypdf, with an optional password.
  - CSV, XLSX and XLS: frappe.utils.csvutils and xlsxutils (out of view); openpyxl writes.
  - MT940: the mt-940 library.
  - ZIP: zipfile in import_supplier_invoice and regional/italy/utils.py.
- **Authentication and sessions:**
  - All of it is Frappe's: session cookie, CSRF token, API keys and login (out of view).
  - ERPNext adds the on_session_creation hook portal/utils.create_customer_or_supplier, the boot hooks (startup/boot.py boot_session and bootinfo) and check_app_permission.
  - banking.html embeds frappe.session.csrf_token and the session boot JSON.
  - Appointment verification uses a frappe.generate_hash key, stored as sha256 and given an expiry by get_verification_link_expiry.
- **Defaults that change exposure:**
  - hooks.py:
    - require_type_annotated_api_methods = True: Frappe type-checks arguments to whitelisted methods (enforcement out of view).
    - use_json_request_body = True.
    - override_whitelisted_methods replaces frappe.www.contact.send_message.
    - website_route_rules and standard_portal_menu_items (portal routes).
    - has_website_permission for 11 doctypes.
    - The "*" permission and validate hooks from company_restriction.
  - HTTP methods: 124 whitelisted functions are limited to POST and 7 to GET; the rest take Frappe's default methods.
  - CI only: .github/helper/site_config_mariadb.json uses fixed test passwords and installs the payments and erpnext apps; run-individual-tests.yml sets allow_tests true.
- **Build and hardening:**
  - No native code. Python is packaged with flit_core; banking is built by Vite with target es2015.
  - Lint and checks: ruff, eslint, prettier and a local postgres-compat hook (.pre-commit-config.yaml).
  - pr-checks.yml runs frappe/semgrep-rules plus r/python.lang.correctness, the local semgrep/test-correctness.yml rules, and pip-audit.
  - dependency-audit.yml runs pip-audit daily on develop, version-16-hotfix and version-15-hotfix.
- **Where routes, schemas and permissions are defined:**
  - Routes: erpnext/hooks.py (website_route_rules, website_generators, standard_portal_menu_items, override_whitelisted_methods), page files under erpnext/www/ and erpnext/templates/pages/, and web forms under */web_form/*.
  - API: @frappe.whitelist decorators (855).
  - Schemas and role permissions: */doctype/*/*.json "fields" and "permissions".
  - Record-level hooks: hooks.py permission_query_conditions, has_permission, has_website_permission and has_upload_permission (Employee).
  - Report roles: */report/*/*.json.
  - erpnext/__init__.py: require_permission, require_user_permission and require_party_permission.
- **Languages** (git-tracked lines, about 647k of code in total):
  - Python 520,677 (about 81%). Of that, tests are 238,417 and patches 17,342.
  - JavaScript 93,927 (about 14.5%).
  - TypeScript/TSX 19,547 (about 3%, all in banking/).
  - HTML/Jinja 8,504 (about 1.3%).
  - CSS/SCSS 4,162.
  - Separately, 370,868 lines of JSON metadata (DocTypes, reports, print formats, workspaces).


<!-- written at these commits:
90e7aefca73da3c440d2e8da7472fcb67838e678 https://github.com/cx-benchmark/erpnext
-->
