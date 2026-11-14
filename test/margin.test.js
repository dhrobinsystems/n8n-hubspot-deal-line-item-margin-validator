'use strict';

/**
 * margin.test.js
 *
 * node --test. No network, no HubSpot portal, no n8n instance required.
 * Covers the config gates, signature checks, rule validation, every fixture,
 * the write plans, the Node.js runner (with a mock HubSpot client), the
 * generated n8n Code nodes executed in a vm sandbox, and a secret/domain scan
 * of every file in the repository.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const config = require('../src/config');
const margin = require('../src/margin');
const runner = require('../src/index');
const build = require('../scripts/build-workflow');
const { validate } = require('../scripts/validate-workflow');

const ROOT = path.join(__dirname, '..');
const FIXTURES = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'deal-line-items.mock.json'), 'utf8'));
const RULES = JSON.parse(fs.readFileSync(path.join(ROOT, 'config', 'margin-rules.example.json'), 'utf8'));
const NOW = Date.UTC(2026, 0, 15, 12, 0, 0);
const SECRET = 'mock_signing_secret_for_tests';
const PUBLIC_URL = 'https://n8n.example.com/webhook/deal-margin-validator';

function plain(value) { return JSON.parse(JSON.stringify(value)); }
function rulesWith(patch) { return Object.assign(plain(RULES), patch); }
function cfg(env) { return config.parseConfig(Object.assign({}, env || {})); }
function fixture(name) { return plain(FIXTURES.cases.find(function (c) { return c.name === name; })); }
function evaluateCase(c, rules) {
  const deal = margin.readDeal({ statusCode: 200, body: c.deal }).deal;
  return { deal: deal, evaluation: margin.evaluateDeal({ deal: deal, lineItems: c.lineItems, products: c.products, rules: rules || RULES }) };
}
function v3Sig(body, ts) { return crypto.createHmac('sha256', SECRET).update('POST' + PUBLIC_URL + body + ts, 'utf8').digest('base64'); }
const b64 = function (s, m) { return crypto.createHmac('sha256', s).update(m, 'utf8').digest('base64'); };
const hex = function (s, m) { return crypto.createHmac('sha256', s).update(m, 'utf8').digest('hex'); };

// ---------------------------------------------------------------- config

test('config defaults are fail-safe', function () {
  const c = cfg();
  assert.equal(c.dryRun, true);
  assert.equal(c.sandboxMode, true);
  assert.equal(c.writeMode, 'dry_run');
  assert.equal(c.writesEnabled, false);
  assert.equal(c.requireSignature, true);
  assert.equal(c.signatureMode, 'hubspot_v3');
  assert.deepEqual(c.proposalStageIds, ['decisionmakerboughtin', 'contractsent']);
  assert.deepEqual(c.pipelineIds, []);
  assert.equal(c.createApprovalTask, true);
  assert.equal(c.notifyOn, 'violations');
  assert.equal(c.recheckUnchanged, false);
});

test('placeholders and blanks count as unset', function () {
  const c = cfg({ DRY_RUN: 'your_dry_run_here', SANDBOX_MODE: '  ', HUBSPOT_SANDBOX_PORTAL_ID: 'your_hubspot_portal_id_here' });
  assert.equal(c.dryRun, true);
  assert.equal(c.sandboxMode, true);
  assert.equal(c.sandboxPortalId, null);
  assert.equal(config.cfgUnset('your_hubspot_private_app_token_here'), true);
  assert.equal(config.cfgUnset('real-looking-value'), false);
});

test('only the literal "false" disables a safety flag', function () {
  assert.equal(cfg({ DRY_RUN: 'no' }).dryRun, true);
  assert.equal(cfg({ DRY_RUN: '0' }).dryRun, true);
  assert.equal(cfg({ DRY_RUN: 'FALSE' }).dryRun, false);
});

test('production mode needs an explicit opt-in', function () {
  assert.throws(function () { cfg({ SANDBOX_MODE: 'false' }); }, /ALLOW_PRODUCTION_MODE/);
  const c = cfg({ SANDBOX_MODE: 'false', ALLOW_PRODUCTION_MODE: 'true', DRY_RUN: 'false' });
  assert.equal(c.writeMode, 'production');
});

test('sandbox writes are their own write mode', function () {
  assert.equal(cfg({ DRY_RUN: 'false' }).writeMode, 'sandbox');
});

test('invalid config values are rejected', function () {
  assert.throws(function () { cfg({ HUBSPOT_BASE_URL: 'http://api.example.com' }); }, /https/);
  assert.throws(function () { cfg({ PROPOSAL_STAGE_IDS: 'contract sent' }); }, /PROPOSAL_STAGE_IDS/);
  assert.throws(function () { cfg({ SIGNATURE_MODE: 'md5' }); }, /SIGNATURE_MODE/);
  assert.throws(function () { cfg({ SIGNATURE_TOLERANCE_SECONDS: '5' }); }, /SIGNATURE_TOLERANCE_SECONDS/);
  assert.throws(function () { cfg({ NOTIFY_ON: 'always' }); }, /NOTIFY_ON/);
  assert.throws(function () { cfg({ HUBSPOT_SANDBOX_PORTAL_ID: 'abc' }); }, /numeric/);
});

test('portal gate allows only sandbox or developer test portals in sandbox mode', function () {
  const c = cfg({ HUBSPOT_SANDBOX_PORTAL_ID: '9001' });
  assert.equal(config.evaluateHubSpotTarget(c, { accountType: 'STANDARD', portalId: 9001 }).allowed, false);
  assert.equal(config.evaluateHubSpotTarget(c, { accountType: 'SANDBOX', portalId: 9002 }).reason, 'sandbox_portal_id_mismatch');
  assert.equal(config.evaluateHubSpotTarget(c, { accountType: 'SANDBOX', portalId: 9001 }).allowed, true);
  assert.equal(config.evaluateHubSpotTarget(cfg(), { accountType: 'DEVELOPER_TEST', portalId: 1 }).allowed, true);
  const prod = cfg({ SANDBOX_MODE: 'false', ALLOW_PRODUCTION_MODE: 'true' });
  assert.equal(config.evaluateHubSpotTarget(prod, { accountType: 'STANDARD' }).allowed, true);
  assert.equal(config.evaluateHubSpotTarget(null, {}).allowed, false);
});

test('loadConfig requires the secrets the chosen mode needs and redacts them', function () {
  assert.throws(function () { config.loadConfig({}); }, /WEBHOOK_SIGNING_SECRET/);
  assert.throws(function () { config.loadConfig({ WEBHOOK_SIGNING_SECRET: SECRET }); }, /WEBHOOK_PUBLIC_URL/);
  assert.throws(function () { config.loadConfig({ REQUIRE_SIGNATURE: 'false', NOTIFICATION_WEBHOOK_URL: 'http://hooks.example.com/x' }); }, /https/);
  const c = config.loadConfig({ WEBHOOK_SIGNING_SECRET: SECRET, WEBHOOK_PUBLIC_URL: PUBLIC_URL, HUBSPOT_PRIVATE_APP_TOKEN: 'mock_token_here' });
  const view = config.describeConfig(c);
  assert.equal(view.webhookSigningSecret, '[redacted]');
  assert.equal(view.hubspotPrivateAppToken, '[redacted]');
  assert.equal(view.auditLogWebhookUrl, null);
  assert.ok(Object.isFrozen(c));
});

// ---------------------------------------------------------------- signatures

test('HubSpot v3 signature: valid, tampered, stale, unconfigured', function () {
  const body = '[{"objectId":1001}]';
  const ts = String(NOW);
  const sig = v3Sig(body, ts);
  assert.equal(margin.verifyHubSpotV3Signature('post', PUBLIC_URL, body, sig, ts, SECRET, NOW, 300, b64).ok, true);
  assert.equal(margin.verifyHubSpotV3Signature('POST', PUBLIC_URL, body + ' ', sig, ts, SECRET, NOW, 300, b64).reason, 'signature_mismatch');
  assert.equal(margin.verifyHubSpotV3Signature('POST', PUBLIC_URL, body, sig, ts, SECRET, NOW + 301000, 300, b64).reason, 'signature_timestamp_outside_tolerance');
  assert.equal(margin.verifyHubSpotV3Signature('POST', PUBLIC_URL, body, sig, ts, 'your_webhook_signing_secret_here', NOW, 300, b64).reason, 'signing_secret_not_configured');
  assert.equal(margin.verifyHubSpotV3Signature('POST', null, body, sig, ts, SECRET, NOW, 300, b64).reason, 'webhook_public_url_not_configured');
  assert.equal(margin.verifyHubSpotV3Signature('POST', PUBLIC_URL, body, null, ts, SECRET, NOW, 300, b64).reason, 'signature_headers_missing');
  assert.equal(margin.verifyHubSpotV3Signature('POST', PUBLIC_URL, body, sig, 'abc', SECRET, NOW, 300, b64).reason, 'signature_headers_malformed');
});

test('generic HMAC signature: valid, malformed, mismatch', function () {
  const body = '{"dealId":1002}';
  const ts = String(Math.floor(NOW / 1000));
  const sig = 'sha256=' + hex(SECRET, ts + '.' + body);
  assert.equal(margin.verifyHmacSignature(body, sig, ts, SECRET, NOW, 300, hex).ok, true);
  assert.equal(margin.verifyHmacSignature(body, 'sha256=zz', ts, SECRET, NOW, 300, hex).reason, 'signature_headers_malformed');
  assert.equal(margin.verifyHmacSignature('{}', sig, ts, SECRET, NOW, 300, hex).reason, 'signature_mismatch');
});

// ---------------------------------------------------------------- rules

test('example rules validate, with warnings for the placeholder owner IDs', function () {
  const r = margin.validateRules(RULES);
  assert.equal(r.ok, true, r.errors.join('; '));
  assert.equal(r.warnings.length, 2);
});

test('invalid rules are reported, never silently accepted', function () {
  const bad = rulesWith({
    version: 2,
    deal: { minimum_margin_pct: 20, target_margin_pct: 50, escalate_below_margin_pct: 30, max_discount_pct: 120 },
    product_rules: [{ match: { sku: 'A', sku_prefix: 'B' } }],
    bundles: [{ name: 'x', required_skus: ['ONLY-ONE'] }],
    data_quality: { missing_cost_policy: 'use_default_cost_ratio', default_cost_ratio: 2 },
    approval: { approver_owner_id: 'abc', escalation_owner_id: '', task_due_hours: 0 }
  });
  const r = margin.validateRules(bad);
  assert.equal(r.ok, false);
  ['version must be 1', 'max_discount_pct must be 0-100', 'escalate_below_margin_pct must not exceed', 'needs exactly one of', 'at least two SKUs', 'default_cost_ratio', 'numeric HubSpot owner ID', 'task_due_hours']
    .forEach(function (needle) { assert.ok(r.errors.some(function (e) { return e.indexOf(needle) !== -1; }), 'expected error containing: ' + needle); });
  const dup = rulesWith({ deal_properties: Object.assign({}, RULES.deal_properties, { hash: 'margin_validation_status' }) });
  assert.ok(margin.validateRules(dup).errors.some(function (e) { return /reuses/.test(e); }));
});

// ---------------------------------------------------------------- events

test('extractDealEvents keeps monitored stage changes and dedupes by deal', function () {
  const c = cfg();
  const out = margin.extractDealEvents([
    { subscriptionType: 'deal.propertyChange', objectId: 1001, propertyName: 'dealstage', propertyValue: 'contractsent', occurredAt: 10, eventId: 1 },
    { subscriptionType: 'deal.propertyChange', objectId: 1001, propertyName: 'dealstage', propertyValue: 'decisionmakerboughtin', occurredAt: 20, eventId: 2 },
    { subscriptionType: 'deal.propertyChange', objectId: 1002, propertyName: 'amount', propertyValue: '5' },
    { subscriptionType: 'deal.propertyChange', objectId: 1003, propertyName: 'dealstage', propertyValue: 'closedwon' },
    { subscriptionType: 'contact.creation', objectId: 1004 },
    { objectId: 'abc' },
    'junk'
  ], c);
  assert.equal(out.deals.length, 1);
  assert.equal(out.deals[0].triggerStage, 'decisionmakerboughtin');
  assert.equal(out.deals[0].eventId, '2');
  assert.deepEqual(out.ignored.map(function (i) { return i.reason.split(':')[0]; }),
    ['not_a_stage_change', 'stage_not_monitored', 'unsupported_subscription_type', 'deal_id_missing', 'not_an_object']);
});

test('extractDealEvents accepts a workflow webhook object with dealId', function () {
  const out = margin.extractDealEvents({ dealId: '1005' }, cfg());
  assert.deepEqual(plain(out.deals), [{ dealId: '1005', triggerStage: null, occurredAt: 0, eventId: null, source: 'workflow.webhook' }]);
});

test('custom proposal stage IDs are honoured', function () {
  const out = margin.extractDealEvents([{ subscriptionType: 'deal.propertyChange', objectId: 1, propertyName: 'dealstage', propertyValue: '123456789' }], cfg({ PROPOSAL_STAGE_IDS: '123456789' }));
  assert.equal(out.deals.length, 1);
});

// ---------------------------------------------------------------- reads

test('request builders produce the documented HubSpot calls', function () {
  const d = margin.buildDealReadRequest('1001', RULES);
  assert.match(d.path, /^\/crm\/v3\/objects\/deals\/1001\?properties=/);
  assert.match(decodeURIComponent(d.path), /margin_validation_hash/);
  assert.match(d.path, /&associations=line_items$/);
  const li = margin.buildLineItemReadRequest(['5001', '5002'], RULES);
  assert.equal(li.path, '/crm/v3/objects/line_items/batch/read');
  assert.ok(li.body.properties.indexOf('approved_custom_unit_price') !== -1);
  assert.equal(margin.buildLineItemReadRequest([], RULES), null);
  const pr = margin.buildProductReadRequest([{ properties: { hs_product_id: '7001' } }, { properties: { hs_product_id: '7001' } }, { properties: {} }], RULES);
  assert.deepEqual(pr.body.inputs, [{ id: '7001' }]);
  assert.equal(margin.buildProductReadRequest([{ properties: {} }], RULES), null);
});

test('readDeal handles both association key spellings, paging, and failures', function () {
  const a = margin.readDeal({ statusCode: 200, body: { id: '1', properties: {}, associations: { line_items: { results: [{ id: 2 }, { id: 2 }], paging: { next: { after: 'x' } } } } } });
  assert.deepEqual(a.lineItemIds, ['2']);
  assert.equal(a.moreLineItems, true);
  assert.equal(a.deal.name, 'Deal 1');
  assert.equal(margin.readDeal({ statusCode: 404, body: {} }).ok, false);
  assert.equal(margin.readBatch({ statusCode: 207, body: { results: [{ id: 1 }] } }).results[0].id, '1');
  assert.equal(margin.readBatch({ statusCode: 400, body: {} }).ok, false);
});

// ---------------------------------------------------------------- evaluation

FIXTURES.cases.forEach(function (c) {
  test('fixture ' + c.name + ' evaluates to ' + c.expect.status, function () {
    const e = evaluateCase(plain(c)).evaluation;
    assert.equal(e.status, c.expect.status);
    assert.equal(e.metrics.marginPct, c.expect.marginPct);
    assert.deepEqual(e.issues.map(function (i) { return i.code; }), c.expect.issueCodes);
    assert.match(e.hash, /^[0-9a-f]{16}$/);
  });
});

test('bundle rule is evaluated when every required SKU is present', function () {
  const e = evaluateCase(fixture('healthy_bundle_passes')).evaluation;
  assert.equal(e.bundles.length, 1);
  assert.equal(e.bundles[0].marginPct, 60);
  const tight = rulesWith({ bundles: [{ name: 'Platform Bundle', required_skus: ['SW-1001', 'SVC-2001'], min_margin_pct: 65, max_combined_discount_pct: 30 }] });
  const e2 = evaluateCase(fixture('healthy_bundle_passes'), tight).evaluation;
  assert.equal(e2.status, 'approval_required');
  assert.deepEqual(e2.issues.map(function (i) { return i.code; }), ['bundle_margin_below_min']);
});

test('bundle combined discount limit applies against list price', function () {
  const c = fixture('healthy_bundle_passes');
  c.lineItems[0].properties.amount = '500';
  c.lineItems[1].properties.amount = '700';
  const e = evaluateCase(c).evaluation;
  assert.ok(e.issues.some(function (i) { return i.code === 'bundle_discount_above_max'; }));
});

test('product rule precedence: exact SKU beats prefix and family', function () {
  const rules = rulesWith({ product_rules: [
    { label: 'prefix', match: { sku_prefix: 'HW-' }, min_margin_pct: 10 },
    { label: 'exact', match: { sku: 'hw-1001' }, min_margin_pct: 15 },
    { label: 'family', match: { product_family: 'Support' }, min_margin_pct: 55 }
  ] });
  assert.equal(margin.matchProductRule('HW-1001', null, null, rules).label, 'exact');
  assert.equal(margin.matchProductRule('HW-2000', null, null, rules).label, 'prefix');
  assert.equal(margin.matchProductRule(null, null, 'support', rules).label, 'family');
  assert.equal(margin.matchProductRule('XX-1', null, null, rules), null);
});

test('net price falls back to price minus discount when amount is missing', function () {
  const line = margin.evaluateLine({ id: '1', properties: { hs_sku: 'SVC-1', quantity: '2', price: '100', discount: '10', hs_cost_of_goods_sold: '50' } }, null, RULES);
  assert.equal(line.netUnitPrice, 90);
  assert.equal(line.discountPct, 10);
  assert.equal(line.marginPct, 44.44);
  assert.deepEqual(line.issues, []);
});

test('selling below cost is a negative-margin escalation', function () {
  const line = margin.evaluateLine({ id: '1', properties: { hs_sku: 'SW-9', quantity: '1', price: '100', amount: '40', hs_cost_of_goods_sold: '60' } }, null, RULES);
  assert.equal(line.marginPct, -50);
  assert.equal(line.issues[0].code, 'negative_margin');
  assert.equal(line.issues[0].severity, 'escalation');
});

test('zero-price lines with cost are reported as -100% margin', function () {
  const line = margin.evaluateLine({ id: '1', properties: { hs_sku: 'SW-9', quantity: '1', price: '0', amount: '0', hs_cost_of_goods_sold: '5' } }, null, RULES);
  assert.equal(line.marginPct, -100);
});

test('missing SKU and zero quantity are surfaced', function () {
  const line = margin.evaluateLine({ id: '1', properties: { quantity: '0', price: '10', hs_cost_of_goods_sold: '1' } }, null, RULES);
  assert.deepEqual(line.issues.map(function (i) { return i.code; }), ['zero_quantity', 'missing_sku']);
});

test('missing_cost_policy "use_default_cost_ratio" estimates cost from list price', function () {
  const rules = rulesWith({ data_quality: { missing_cost_policy: 'use_default_cost_ratio', default_cost_ratio: 0.3, require_sku: true } });
  const e = evaluateCase(fixture('missing_cost_is_incomplete'), rules).evaluation;
  assert.equal(e.status, 'passed');
  assert.equal(e.lines[1].costSource, 'default_cost_ratio');
  assert.equal(e.metrics.costCoveragePct, 100);
});

test('missing_cost_policy "fail" turns a missing cost into an approval', function () {
  const rules = rulesWith({ data_quality: { missing_cost_policy: 'fail', default_cost_ratio: null, require_sku: true } });
  assert.equal(evaluateCase(fixture('missing_cost_is_incomplete'), rules).evaluation.status, 'approval_required');
});

test('deals without line items get their own status', function () {
  const e = margin.evaluateDeal({ deal: { id: '9', name: 'x' }, lineItems: [], products: [], rules: RULES });
  assert.equal(e.status, 'no_line_items');
  assert.equal(e.approvalRequired, false);
  assert.equal(e.metrics.marginPct, null);
});

test('currency mismatch and truncated line items become warnings', function () {
  const c = fixture('healthy_bundle_passes');
  const deal = margin.readDeal({ statusCode: 200, body: c.deal }).deal;
  deal.currency = 'EUR';
  const e = margin.evaluateDeal({ deal: deal, lineItems: c.lineItems, products: c.products, rules: RULES, moreLineItems: true });
  assert.deepEqual(e.warnings, ['more_than_100_line_items_only_first_100_evaluated', 'deal_currency_EUR_differs_from_rules_currency_USD']);
});

test('evaluation hash is stable and changes with pricing or rules', function () {
  const a = evaluateCase(fixture('software_discount_needs_approval')).evaluation.hash;
  assert.equal(evaluateCase(fixture('software_discount_needs_approval')).evaluation.hash, a);
  const c = fixture('software_discount_needs_approval');
  c.lineItems[0].properties.amount = '750';
  assert.notEqual(evaluateCase(c).evaluation.hash, a);
  assert.notEqual(evaluateCase(fixture('software_discount_needs_approval'), rulesWith({ deal: Object.assign({}, RULES.deal, { minimum_margin_pct: 36 }) })).evaluation.hash, a);
});

// ---------------------------------------------------------------- write plans

test('deal update writes every configured property', function () {
  const x = evaluateCase(fixture('software_discount_needs_approval'));
  const u = margin.buildDealUpdate(x.evaluation, x.deal, RULES, cfg(), NOW);
  assert.equal(u.skip, false);
  assert.deepEqual(Object.keys(u.properties).sort(), Object.values(RULES.deal_properties).sort());
  assert.equal(u.properties.margin_validation_status, 'approval_required');
  assert.equal(u.properties.margin_approval_required, 'true');
  assert.equal(u.properties.margin_validation_checked_at, String(NOW));
  assert.match(u.properties.margin_validation_violations, /^\[APPROVAL\] SW-1001: discount_above_max/);
});

test('unchanged deals are skipped unless RECHECK_UNCHANGED=true', function () {
  const x = evaluateCase(fixture('software_discount_needs_approval'));
  x.deal.properties.margin_validation_hash = x.evaluation.hash;
  x.deal.properties.margin_validation_status = x.evaluation.status;
  assert.equal(margin.buildDealUpdate(x.evaluation, x.deal, RULES, cfg(), NOW).skip, true);
  assert.equal(margin.buildDealUpdate(x.evaluation, x.deal, RULES, cfg({ RECHECK_UNCHANGED: 'true' }), NOW).skip, false);
});

test('approval task needs a real owner ID and targets escalation owners when escalating', function () {
  const x = evaluateCase(fixture('hardware_below_floor_escalates'));
  assert.equal(margin.buildApprovalTask(x.evaluation, x.deal, RULES, cfg(), NOW).reason, 'approver_owner_id_not_configured');
  const owners = rulesWith({ approval: { approver_owner_id: '4001', escalation_owner_id: '4002', task_due_hours: 24 } });
  const t = margin.buildApprovalTask(x.evaluation, x.deal, owners, cfg(), NOW).task;
  assert.equal(t.properties.hubspot_owner_id, '4002');
  assert.equal(t.properties.hs_task_priority, 'HIGH');
  assert.match(t.properties.hs_task_subject, /^ESCALATION: Margin approval needed: Mock Deal Charlie/);
  assert.equal(t.properties.hs_timestamp, String(NOW + 24 * 3600000));
  assert.equal(t.associationTypeId, 216);
  const y = evaluateCase(fixture('software_discount_needs_approval'));
  assert.equal(margin.buildApprovalTask(y.evaluation, y.deal, owners, cfg(), NOW).task.properties.hubspot_owner_id, '4001');
  assert.equal(margin.buildApprovalTask(y.evaluation, y.deal, owners, cfg({ CREATE_APPROVAL_TASK: 'false' }), NOW).reason, 'approval_tasks_disabled');
  const z = evaluateCase(fixture('healthy_bundle_passes'));
  assert.equal(margin.buildApprovalTask(z.evaluation, z.deal, owners, cfg(), NOW).reason, 'no_approval_required');
});

test('notifications respect NOTIFY_ON and label sandbox traffic', function () {
  const approval = evaluateCase(fixture('software_discount_needs_approval')).evaluation;
  const escalation = evaluateCase(fixture('hardware_below_floor_escalates')).evaluation;
  const passed = evaluateCase(fixture('healthy_bundle_passes')).evaluation;
  assert.match(margin.buildNotification(approval, cfg()).text, /^\[SANDBOX\] :warning: Margin approval needed on deal 1002/);
  assert.equal(margin.buildNotification(passed, cfg()), null);
  assert.equal(margin.buildNotification(approval, cfg({ NOTIFY_ON: 'escalations' })), null);
  assert.ok(margin.buildNotification(escalation, cfg({ NOTIFY_ON: 'escalations' })));
  assert.equal(margin.buildNotification(escalation, cfg({ NOTIFY_ON: 'none' })), null);
});

test('violation summary is capped for the HubSpot text property', function () {
  const issues = [];
  for (let i = 0; i < 200; i++) issues.push({ scope: 'line', sku: 'SW-' + i, code: 'line_margin_below_min', severity: 'approval', detail: 'margin 1% < 60%' });
  const text = margin.summarizeIssues(issues);
  assert.equal(text.length, 4000);
  assert.ok(text.endsWith('…'));
});

test('audit entries carry codes and metrics but no names', function () {
  const e = evaluateCase(fixture('hardware_below_floor_escalates')).evaluation;
  const a = margin.buildAuditEntry('1003', e, 'dry_run_escalation_required', 'dry_run', '2026-01-15T12:00:00.000Z');
  assert.equal(a.approvalRequired, true);
  assert.ok(a.issueCodes.indexOf('below_floor_price') !== -1);
  assert.equal(JSON.stringify(a).indexOf('Mock Deal'), -1);
});

// ---------------------------------------------------------------- Node.js runner

function mockHubSpot(caseData, overrides) {
  const calls = [];
  const o = overrides || {};
  return {
    calls: calls,
    request: async function (method, p, body) {
      calls.push({ method: method, path: p, body: body });
      if (method === 'GET' && p.indexOf('/crm/v3/objects/deals/') === 0) return { statusCode: 200, body: o.deal || caseData.deal };
      if (p === '/crm/v3/objects/line_items/batch/read') return { statusCode: 200, body: { results: caseData.lineItems } };
      if (p === '/crm/v3/objects/products/batch/read') return { statusCode: 200, body: { results: caseData.products } };
      if (method === 'PATCH') return { statusCode: o.patchStatus || 200, body: { id: caseData.deal.id } };
      if (method === 'POST' && p === '/crm/v3/objects/tasks') return { statusCode: 201, body: { id: '8001' } };
      return { statusCode: 404, body: null };
    }
  };
}

test('runner in DRY_RUN reads only and returns the full plan', async function () {
  const c = fixture('software_discount_needs_approval');
  const hubspot = mockHubSpot(c);
  const out = await runner.validateDeal({ dealId: '1002' }, { cfg: cfg(), rules: RULES, hubspot: hubspot, now: function () { return NOW; } });
  assert.equal(out.outcome, 'dry_run_approval_required');
  assert.deepEqual(hubspot.calls.map(function (x) { return x.method; }), ['GET', 'POST', 'POST']);
  assert.equal(out.plan.dealUpdate.properties.margin_validation_status, 'approval_required');
  assert.equal(out.audit.writeMode, 'dry_run');
});

test('runner in sandbox writes the deal and the approval task', async function () {
  const c = fixture('hardware_below_floor_escalates');
  const hubspot = mockHubSpot(c);
  const owners = rulesWith({ approval: { approver_owner_id: '4001', escalation_owner_id: '4002', task_due_hours: 24 } });
  const out = await runner.validateDeal({ dealId: '1003' }, { cfg: cfg({ DRY_RUN: 'false' }), rules: owners, hubspot: hubspot, now: function () { return NOW; } });
  assert.equal(out.outcome, 'written_escalation_required');
  const patch = hubspot.calls.find(function (x) { return x.method === 'PATCH'; });
  assert.equal(patch.path, '/crm/v3/objects/deals/1003');
  const task = hubspot.calls.find(function (x) { return x.path === '/crm/v3/objects/tasks'; });
  assert.equal(task.body.associations[0].types[0].associationTypeId, 216);
  assert.deepEqual(out.actions.map(function (a) { return a.action + ':' + a.ok; }), ['deal_update:true', 'approval_task:true']);
});

test('runner stops on a failed deal update without creating a task', async function () {
  const c = fixture('hardware_below_floor_escalates');
  const hubspot = mockHubSpot(c, { patchStatus: 403 });
  const owners = rulesWith({ approval: { approver_owner_id: '4001', escalation_owner_id: '4002', task_due_hours: 24 } });
  const out = await runner.validateDeal({ dealId: '1003' }, { cfg: cfg({ DRY_RUN: 'false' }), rules: owners, hubspot: hubspot, now: function () { return NOW; } });
  assert.equal(out.outcome, 'deal_update_failed');
  assert.equal(hubspot.calls.some(function (x) { return x.path === '/crm/v3/objects/tasks'; }), false);
});

test('runner skips deals that already left the proposal stage', async function () {
  const c = fixture('healthy_bundle_passes');
  c.deal.properties.dealstage = 'closedwon';
  const hubspot = mockHubSpot(c);
  const out = await runner.validateDeal({ dealId: '1001' }, { cfg: cfg({ DRY_RUN: 'false' }), rules: RULES, hubspot: hubspot, now: function () { return NOW; } });
  assert.equal(out.outcome, 'skipped_deal_left_proposal_stage');
  assert.equal(hubspot.calls.length, 1);
});

test('runner refuses the example rules once writes are enabled', function () {
  assert.throws(function () { runner.loadRules({}, cfg({ DRY_RUN: 'false' })); }, /example rules/);
  assert.equal(runner.loadRules({}, cfg()).rules.version, 1);
  assert.throws(function () { runner.loadRules({ MARGIN_RULES_JSON: '{' }, cfg()); }, /not valid JSON/);
  assert.throws(function () { runner.loadRules({ MARGIN_RULES_JSON: '{"version":1}' }, cfg()); }, /invalid/);
});

test('runner fixture mode evaluates every case offline', function () {
  const out = runner.evaluateFixture(path.join(__dirname, 'fixtures', 'deal-line-items.mock.json'), { cfg: cfg(), rules: RULES, now: function () { return NOW; } });
  assert.deepEqual(out.map(function (o) { return o.evaluation.status; }), FIXTURES.cases.map(function (c) { return c.expect.status; }));
});

// ---------------------------------------------------------------- n8n workflow

const WORKFLOW = JSON.parse(fs.readFileSync(path.join(ROOT, 'workflow.json'), 'utf8'));
function node(name) { return WORKFLOW.nodes.find(function (n) { return n.name === name; }); }

class FixedDate extends Date {
  constructor() { if (arguments.length) super(...arguments); else super(NOW); }
  static now() { return NOW; }
}

async function runCode(name, opts) {
  const o = opts || {};
  const items = o.items || [{ json: o.json || {} }];
  const envProxy = o.blockEnv
    ? new Proxy({}, { get: function () { throw new Error('access to env vars denied'); } })
    : Object.assign({}, o.env || {});
  const sandbox = {
    $input: { first: function () { return items[0]; }, all: function () { return items; }, item: items[0] },
    $json: items[0].json,
    $env: envProxy,
    $: function (ref) {
      const data = (o.refs || {})[ref];
      if (!data) throw new Error('No data for node ' + ref);
      return { first: function () { return { json: data }; }, item: { json: data } };
    },
    require: require,
    Date: FixedDate,
    console: console,
    unescape: unescape,
    encodeURIComponent: encodeURIComponent,
    BigInt: BigInt
  };
  const self = { helpers: { getBinaryDataBuffer: async function () { if (o.rawBody === undefined) throw new Error('no binary'); return Buffer.from(o.rawBody, 'utf8'); } } };
  const fn = vm.runInNewContext('(async function () {\n' + node(name).parameters.jsCode + '\n})', sandbox);
  return plain(await fn.call(self));
}

test('workflow.json is generated from src/ and up to date', function () {
  assert.equal(fs.readFileSync(path.join(ROOT, 'workflow.json'), 'utf8'), build.output);
});

test('workflow.json passes structural validation', function () {
  const r = validate(WORKFLOW);
  assert.equal(r.ok, true, r.errors.join('; '));
  assert.equal(r.nodeCount, 28);
  WORKFLOW.nodes.filter(function (n) { return n.credentials; }).forEach(function (n) {
    assert.equal(n.credentials.hubspotAppToken.id, 'your_n8n_credential_id_here');
  });
});

test('workflow validator catches broken workflows', function () {
  const broken = plain(WORKFLOW);
  broken.active = true;
  broken.nodes.find(function (n) { return n.name === 'Update Deal Properties'; }).onError = undefined;
  broken.nodes.find(function (n) { return n.name === 'Get Deal'; }).credentials.hubspotAppToken.id = '123';
  broken.connections['Ghost'] = { main: [[{ node: 'Nowhere', type: 'main', index: 0 }]] };
  const r = validate(broken);
  assert.equal(r.ok, false);
  assert.ok(r.errors.length >= 4);
});

function signedRequest(bodyObj) {
  const body = JSON.stringify(bodyObj);
  const ts = String(NOW);
  return { rawBody: body, json: { headers: { 'X-HubSpot-Signature-v3': v3Sig(body, ts), 'X-HubSpot-Request-Timestamp': ts }, body: bodyObj } };
}
const BASE_ENV = { WEBHOOK_SIGNING_SECRET: SECRET, WEBHOOK_PUBLIC_URL: PUBLIC_URL };
const EVENTS = [{ subscriptionType: 'deal.propertyChange', objectId: 1002, propertyName: 'dealstage', propertyValue: 'contractsent', occurredAt: 1 }];

test('n8n Verify & Extract accepts a valid HubSpot v3 signature', async function () {
  const req = signedRequest(EVENTS);
  const out = await runCode('Verify & Extract', { json: req.json, rawBody: req.rawBody, env: BASE_ENV });
  assert.equal(out[0].json.accepted, true);
  assert.equal(out[0].json.httpStatus, 202);
  assert.equal(out[0].json.rulesSource, 'embedded_example_rules_dry_run_only');
  assert.deepEqual(out[0].json.deals.map(function (d) { return d.dealId; }), ['1002']);
  assert.equal(JSON.stringify(out).indexOf(SECRET), -1, 'the signing secret must never reach item data');
});

test('n8n Verify & Extract rejects tampered bodies and blocked env access', async function () {
  const req = signedRequest(EVENTS);
  const tampered = await runCode('Verify & Extract', { json: req.json, rawBody: req.rawBody.replace('1002', '1003'), env: BASE_ENV });
  assert.equal(tampered[0].json.httpStatus, 401);
  assert.equal(tampered[0].json.response.reason, 'signature_mismatch');
  const blocked = await runCode('Verify & Extract', { json: req.json, rawBody: req.rawBody, blockEnv: true });
  assert.equal(blocked[0].json.httpStatus, 401);
  assert.equal(blocked[0].json.response.reason, 'signing_secret_not_configured');
  assert.equal(blocked[0].json.envBlocked, true);
  const noRaw = await runCode('Verify & Extract', { json: req.json, env: BASE_ENV });
  assert.equal(noRaw[0].json.httpStatus, 400);
});

test('n8n Verify & Extract refuses example rules when writes are enabled', async function () {
  const req = signedRequest(EVENTS);
  const out = await runCode('Verify & Extract', { json: req.json, rawBody: req.rawBody, env: Object.assign({ DRY_RUN: 'false' }, BASE_ENV) });
  assert.equal(out[0].json.httpStatus, 500);
  assert.equal(out[0].json.response.reason, 'margin_rules_not_configured_set_MARGIN_RULES_JSON');
  const ok = await runCode('Verify & Extract', { json: req.json, rawBody: req.rawBody, env: Object.assign({ DRY_RUN: 'false', MARGIN_RULES_JSON: JSON.stringify(RULES) }, BASE_ENV) });
  assert.equal(ok[0].json.accepted, true);
  assert.equal(ok[0].json.rulesSource, 'MARGIN_RULES_JSON');
});

test('n8n Portal Gate blocks a standard portal in sandbox mode', async function () {
  const verified = { cfg: plain(cfg()), rules: RULES, rulesSource: 'x', deals: [{ dealId: '1002' }], ignored: [] };
  const blocked = await runCode('Portal Gate', { json: { statusCode: 200, body: { accountType: 'STANDARD', portalId: 1 } }, refs: { 'Verify & Extract': verified } });
  assert.equal(blocked[0].json.allowed, false);
  assert.match(blocked[0].json.reason, /sandbox_mode_requires/);
  const allowed = await runCode('Portal Gate', { json: { statusCode: 200, body: { accountType: 'SANDBOX', portalId: 1 } }, refs: { 'Verify & Extract': verified } });
  assert.equal(allowed[0].json.allowed, true);
  assert.match(allowed[0].json.dealPath, /^\/crm\/v3\/objects\/deals\/1002\?/);
});

test('n8n per-deal chain matches the Node.js engine (parity)', async function () {
  const c = fixture('hardware_below_floor_escalates');
  const queued = { cfg: plain(cfg({ DRY_RUN: 'false' })), rules: RULES, dealEvent: { dealId: '1003' } };
  const prepared = await runCode('Prepare Line Items', { json: { statusCode: 200, body: c.deal }, refs: { 'Portal Gate': queued } });
  assert.equal(prepared.json.proceed, true);
  assert.equal(prepared.json.hasLineItems, true);
  const collected = await runCode('Collect Line Items', { json: { statusCode: 200, body: { results: c.lineItems } }, refs: { 'Prepare Line Items': prepared.json } });
  assert.equal(collected.json.hasProducts, true);
  const evaluated = await runCode('Evaluate Margins', { json: { statusCode: 200, body: { results: c.products } }, refs: { 'Collect Line Items': collected.json } });
  const direct = evaluateCase(c).evaluation;
  assert.deepEqual(evaluated.json.evaluation, plain(direct));
  assert.equal(evaluated.json.writeNow, true);
  assert.equal(evaluated.json.dealUpdateBody.properties.margin_validation_checked_at, String(NOW));
  assert.equal(evaluated.json.createTask, false, 'placeholder approver IDs must not create tasks');
});

test('n8n Evaluate Margins handles the no-line-items branch', async function () {
  const prepared = { __stage: 'deal_prepared', cfg: plain(cfg()), rules: RULES, dealId: '9', dealEvent: { dealId: '9' }, deal: { id: '9', name: 'x', properties: {} }, proceed: true, hasLineItems: false };
  const out = await runCode('Evaluate Margins', { json: prepared });
  assert.equal(out.json.evaluation.status, 'no_line_items');
  assert.equal(out.json.outcome, 'dry_run_no_line_items');
  assert.equal(out.json.writeNow, false);
});

test('n8n Build Notification and Build Audit Entry never expose webhook URLs', async function () {
  const c = fixture('software_discount_needs_approval');
  const ev = evaluateCase(c).evaluation;
  const evaluatedItem = { cfg: plain(cfg({ DRY_RUN: 'false' })), dealId: '1002', evaluation: plain(ev), actions: [], createTask: true, approvalTask: { task: {}, reason: null }, notification: margin.buildNotification(ev, cfg()) };
  const hook = 'https://hooks.example.com/services/mock_path_here';
  const notify = await runCode('Build Notification', { json: { id: '8001', properties: { hs_task_subject: 'x' } }, refs: { 'Evaluate Margins': evaluatedItem }, env: { SANDBOX_NOTIFICATION_WEBHOOK_URL: hook } });
  assert.equal(notify.json.sendNotification, true);
  assert.equal(notify.json.notifyTarget, 'sandbox');
  assert.deepEqual(notify.json.actions.map(function (a) { return a.action + ':' + a.ok; }), ['deal_update:true', 'approval_task:true']);
  assert.equal(JSON.stringify(notify).indexOf(hook), -1);
  const audit = await runCode('Build Audit Entry', { json: { statusCode: 200 }, refs: { 'Build Notification': notify.json }, env: { AUDIT_LOG_WEBHOOK_URL: hook } });
  assert.equal(audit.json.outcome, 'written_approval_required');
  assert.equal(audit.json.forwardAudit, true);
  assert.equal(audit.json.actions[2].action, 'notification');
  assert.equal(JSON.stringify(audit).indexOf(hook), -1);
  assert.equal(audit.json.at, new Date(NOW).toISOString());
});

test('n8n Build Audit Entry records a blocked batch', async function () {
  const out = await runCode('Build Audit Entry', { json: { __stage: 'blocked', allowed: false, reason: 'sandbox_mode_requires_x', writeMode: 'dry_run', ignored: [{}] } });
  assert.equal(out.json.outcome, 'portal_gate_blocked:sandbox_mode_requires_x');
  assert.equal(out.json.ignoredEvents, 1);
  assert.equal(out.json.forwardAudit, false);
});

// ---------------------------------------------------------------- repository hygiene

function listFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(function (entry) {
    if (entry.name === 'node_modules' || entry.name === '.git') return [];
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? listFiles(full) : [full];
  });
}

const SECRET_PATTERNS = [
  { name: 'private key block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'HubSpot private app token', re: /\bpat-(na|eu)[0-9]-[0-9a-f-]{20,}/i },
  { name: 'HubSpot API key parameter', re: /hapikey=[0-9a-f-]{8,}/i },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{30,}/ },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { name: 'Slack webhook', re: /hooks\.slack\.com\/services\/T[A-Z0-9]+/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'hard-coded secret assignment', re: /(?:TOKEN|SECRET|API_KEY|PASSWORD)[ \t]*[=:][ \t]*["']?(?!your_[a-z0-9_]+_here|mock_|REPLACE_WITH_|\$|\{\{|process\.env|cfg|env|null|''|""|\[redacted\])[A-Za-z0-9_\-\/+]{16,}/ }
];
const ALLOWED_DOMAINS = {
  'dhrobinsystems.com': 'author attribution',
  'behance.net': 'author portfolio link',
  'linkedin.com': 'author profile link',
  'github.com': 'repository and license links',
  'api.hubapi.com': 'HubSpot public API base URL',
  'developers.hubspot.com': 'HubSpot developer documentation',
  'docs.n8n.io': 'n8n documentation',
  'nodejs.org': 'Node.js download link',
  'opensource.org': 'MIT license reference'
};

function domainAllowed(domain) {
  const d = domain.toLowerCase();
  if (/(^|\.)example\.(com|org|net)$/.test(d)) return true;
  return Object.keys(ALLOWED_DOMAINS).some(function (a) { return d === a || d.endsWith('.' + a); });
}

function scanText(text) {
  const findings = [];
  SECRET_PATTERNS.forEach(function (p) { if (p.re.test(text)) findings.push(p.name); });
  const urlRe = /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi;
  let m;
  while ((m = urlRe.exec(text))) if (!domainAllowed(m[1])) findings.push('domain ' + m[1]);
  const emailRe = /[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;
  while ((m = emailRe.exec(text))) {
    if (!domainAllowed(m[1])) findings.push('email domain ' + m[1]);
  }
  return findings;
}

test('security scanner detects planted secrets (self-test)', function () {
  assert.ok(scanText('API_KEY=abcdefghijklmnopqrstuvwx').length);
  assert.ok(scanText('mail someone@real-company-domain.io').length);
  assert.deepEqual(scanText('HUBSPOT_PRIVATE_APP_TOKEN=your_hubspot_private_app_token_here https://n8n.example.com robin@dhrobinsystems.com'), []);
});

test('no secrets, real domains, or personal emails anywhere in the repository', function () {
  const problems = [];
  listFiles(ROOT).forEach(function (file) {
    const rel = path.relative(ROOT, file);
    if (rel === path.join('test', 'margin.test.js')) return;
    if (/\.(zip|png|jpg|gif)$/i.test(rel)) return;
    scanText(fs.readFileSync(file, 'utf8')).forEach(function (f) { problems.push(rel + ': ' + f); });
  });
  assert.deepEqual(problems, []);
});

test('the required disclaimer line appears in README.md and DISCLAIMER.md', function () {
  const line = 'DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.';
  ['README.md', 'DISCLAIMER.md'].forEach(function (f) {
    assert.ok(fs.readFileSync(path.join(ROOT, f), 'utf8').indexOf(line) !== -1, f + ' is missing the disclaimer line');
  });
  assert.match(fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8'), /^MIT License\n\nCopyright \(c\) 2026 dhRobin Systems/);
});