'use strict';

/**
 * index.js
 *
 * Standalone Node.js mirror of workflow.json. Same logic (src/margin.js), same
 * safety gates (src/config.js), no n8n required.
 *
 *   node src/index.js                         start the webhook server (POST /webhook)
 *   node src/index.js --fixture <file.json>   evaluate a mock deal offline (no network)
 *   node src/index.js --deal <dealId>         validate one deal against HubSpot now
 *   node src/index.js --check-rules           validate the margin rules file and exit
 *
 * Requires Node.js 18+ (global fetch). No runtime dependencies.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { loadConfig, describeConfig, evaluateHubSpotTarget, cfgUnset } = require('./config');
const margin = require('./margin');

const MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_RULES_FILE = path.join(__dirname, '..', 'config', 'margin-rules.example.json');

function log(level, message, extra) {
  const line = Object.assign({ at: new Date().toISOString(), level: level, message: message }, extra || {});
  (level === 'error' ? process.stderr : process.stdout).write(JSON.stringify(line) + '\n');
}

function loadRules(env, cfg) {
  let raw;
  let source;
  if (!cfgUnset(env.MARGIN_RULES_JSON)) {
    raw = String(env.MARGIN_RULES_JSON);
    source = 'MARGIN_RULES_JSON';
  } else if (cfg.marginRulesFile) {
    source = path.resolve(cfg.marginRulesFile);
    raw = fs.readFileSync(source, 'utf8');
  } else if (!cfg.writesEnabled) {
    // The example thresholds are only good enough for a dry run.
    source = DEFAULT_RULES_FILE;
    raw = fs.readFileSync(source, 'utf8');
  } else {
    throw new Error('Writes are enabled (DRY_RUN=false) but neither MARGIN_RULES_FILE nor MARGIN_RULES_JSON is set. I refuse to write verdicts based on the example rules.');
  }
  let rules;
  try { rules = JSON.parse(raw); } catch (err) { throw new Error('Margin rules (' + source + ') are not valid JSON: ' + err.message); }
  const check = margin.validateRules(rules);
  if (!check.ok) throw new Error('Margin rules (' + source + ') are invalid:\n  - ' + check.errors.join('\n  - '));
  return { rules: rules, source: source, warnings: check.warnings };
}

function hmacBase64(secret, message) {
  return crypto.createHmac('sha256', secret).update(message, 'utf8').digest('base64');
}

function hmacHex(secret, message) {
  return crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
}

function createHubSpotClient(cfg) {
  if (!cfg.hubspotPrivateAppToken) throw new Error('HUBSPOT_PRIVATE_APP_TOKEN is blank or a placeholder.');
  async function request(method, requestPath, body) {
    for (let attempt = 1; attempt <= 3; attempt++) {
      const res = await fetch(cfg.hubspotBaseUrl + requestPath, {
        method: method,
        headers: Object.assign({ Authorization: 'Bearer ' + cfg.hubspotPrivateAppToken, Accept: 'application/json' }, body ? { 'Content-Type': 'application/json' } : {}),
        body: body ? JSON.stringify(body) : undefined
      });
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; } catch (err) { parsed = { raw: text.slice(0, 500) }; }
      if ((res.status === 429 || res.status >= 500) && attempt < 3) {
        await new Promise(function (r) { setTimeout(r, attempt * 1500); });
        continue;
      }
      return { statusCode: res.status, body: parsed };
    }
    return { statusCode: 0, body: null };
  }
  return { request: request };
}

async function postJson(url, payload) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  return { statusCode: res.status };
}

/** Pure-ish pipeline: everything except the HTTP client and clock is deterministic. */
async function validateDeal(dealEvent, ctx) {
  const cfg = ctx.cfg;
  const rules = ctx.rules;
  const nowMs = ctx.now();
  const atIso = new Date(nowMs).toISOString();
  const result = { dealId: dealEvent.dealId, writeMode: cfg.writeMode, actions: [] };

  const dealRes = await ctx.hubspot.request('GET', margin.buildDealReadRequest(dealEvent.dealId, rules).path);
  const dealRead = margin.readDeal(dealRes);
  if (!dealRead.ok) return Object.assign(result, { outcome: 'deal_read_failed', httpStatus: dealRead.status });
  const deal = dealRead.deal;
  if (cfg.proposalStageIds.indexOf(deal.stage) === -1) return Object.assign(result, { outcome: 'skipped_deal_left_proposal_stage', stage: deal.stage });
  if (cfg.pipelineIds.length && cfg.pipelineIds.indexOf(deal.pipeline) === -1) return Object.assign(result, { outcome: 'skipped_pipeline_not_monitored', pipeline: deal.pipeline });

  let lineItems = [];
  const liReq = margin.buildLineItemReadRequest(dealRead.lineItemIds, rules);
  if (liReq) {
    const liRead = margin.readBatch(await ctx.hubspot.request(liReq.method, liReq.path, liReq.body));
    if (!liRead.ok) return Object.assign(result, { outcome: 'line_item_read_failed' });
    lineItems = liRead.results;
  }
  let products = [];
  const prReq = margin.buildProductReadRequest(lineItems, rules);
  if (prReq) {
    const prRead = margin.readBatch(await ctx.hubspot.request(prReq.method, prReq.path, prReq.body));
    products = prRead.ok ? prRead.results : [];
    if (!prRead.ok) result.actions.push({ action: 'product_read', ok: false, note: 'evaluated with line-item data only' });
  }

  const evaluation = margin.evaluateDeal({ deal: deal, lineItems: lineItems, products: products, rules: rules, moreLineItems: dealRead.moreLineItems });
  result.evaluation = evaluation;
  const update = margin.buildDealUpdate(evaluation, deal, rules, cfg, nowMs);
  const task = margin.buildApprovalTask(evaluation, deal, rules, cfg, nowMs);
  const notification = margin.buildNotification(evaluation, cfg);
  result.plan = { dealUpdate: update, approvalTask: task, notification: notification };

  if (!cfg.writesEnabled) {
    result.outcome = 'dry_run_' + evaluation.status;
  } else if (update.skip) {
    result.outcome = 'unchanged_' + evaluation.status;
  } else {
    const patch = await ctx.hubspot.request('PATCH', '/crm/v3/objects/deals/' + encodeURIComponent(deal.id), { properties: update.properties });
    result.actions.push({ action: 'deal_update', ok: patch.statusCode === 200, httpStatus: patch.statusCode });
    if (patch.statusCode !== 200) {
      result.outcome = 'deal_update_failed';
    } else {
      if (task.task) {
        const created = await ctx.hubspot.request('POST', '/crm/v3/objects/tasks', {
          properties: task.task.properties,
          associations: [{ to: { id: deal.id }, types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: task.task.associationTypeId }] }]
        });
        result.actions.push({ action: 'approval_task', ok: created.statusCode === 201, httpStatus: created.statusCode, taskId: created.body && created.body.id ? String(created.body.id) : null });
      } else if (evaluation.approvalRequired) {
        result.actions.push({ action: 'approval_task', ok: false, skipped: task.reason });
      }
      const target = cfg.sandboxMode ? cfg.sandboxNotificationWebhookUrl : cfg.notificationWebhookUrl;
      if (notification && target) {
        try {
          const sent = await postJson(target, notification);
          result.actions.push({ action: 'notification', ok: sent.statusCode >= 200 && sent.statusCode < 300, httpStatus: sent.statusCode });
        } catch (err) {
          result.actions.push({ action: 'notification', ok: false, error: err.message });
        }
      }
      result.outcome = 'written_' + evaluation.status;
    }
  }

  const audit = margin.buildAuditEntry(deal.id, evaluation, result.outcome, cfg.writeMode, atIso);
  result.audit = audit;
  if (cfg.auditLogWebhookUrl) {
    try { await postJson(cfg.auditLogWebhookUrl, audit); } catch (err) { log('error', 'audit_forward_failed', { error: err.message }); }
  }
  return result;
}

async function checkPortal(ctx) {
  const res = await ctx.hubspot.request('GET', '/account-info/v3/details');
  if (res.statusCode !== 200) return { allowed: false, reason: 'account_details_unavailable_http_' + res.statusCode };
  return evaluateHubSpotTarget(ctx.cfg, res.body || {});
}

function readBody(req) {
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let size = 0;
    req.on('data', function (chunk) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('payload_too_large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', function () { resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}

function verifyRequest(req, rawBody, cfg, nowMs) {
  if (!cfg.requireSignature) return { ok: true, reason: 'signature_check_disabled' };
  if (cfg.signatureMode === 'hubspot_v3') {
    return margin.verifyHubSpotV3Signature(req.method, cfg.webhookPublicUrl, rawBody, req.headers['x-hubspot-signature-v3'], req.headers['x-hubspot-request-timestamp'],
      cfg.webhookSigningSecret, nowMs, cfg.signatureToleranceSeconds, hmacBase64);
  }
  return margin.verifyHmacSignature(rawBody, req.headers['x-signature'], req.headers['x-signature-timestamp'], cfg.webhookSigningSecret, nowMs, cfg.signatureToleranceSeconds, hmacHex);
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function startServer(ctx) {
  const server = http.createServer(async function (req, res) {
    if (req.method === 'GET' && req.url === '/healthz') return send(res, 200, { ok: true, writeMode: ctx.cfg.writeMode });
    if (req.method !== 'POST' || req.url.split('?')[0] !== '/webhook') return send(res, 404, { error: 'not_found' });
    let rawBody;
    try { rawBody = await readBody(req); } catch (err) { return send(res, 413, { error: 'payload_too_large' }); }
    const sig = verifyRequest(req, rawBody, ctx.cfg, ctx.now());
    if (!sig.ok) { log('warn', 'webhook_rejected', { reason: sig.reason }); return send(res, 401, { error: 'unauthorized', reason: sig.reason }); }
    let payload;
    try { payload = JSON.parse(rawBody); } catch (err) { return send(res, 400, { error: 'invalid_json' }); }
    const extracted = margin.extractDealEvents(payload, ctx.cfg);
    send(res, 202, { accepted: extracted.deals.length, ignored: extracted.ignored.length, writeMode: ctx.cfg.writeMode });
    if (!extracted.deals.length) return;
    try {
      const gate = await checkPortal(ctx);
      if (!gate.allowed) { log('error', 'portal_gate_blocked', { reason: gate.reason }); return; }
      for (const dealEvent of extracted.deals) {
        try {
          const outcome = await validateDeal(dealEvent, ctx);
          log('info', 'deal_validated', { dealId: outcome.dealId, outcome: outcome.outcome, audit: outcome.audit || null, actions: outcome.actions });
        } catch (err) {
          log('error', 'deal_validation_failed', { dealId: dealEvent.dealId, error: err.message });
        }
      }
    } catch (err) {
      log('error', 'batch_failed', { error: err.message });
    }
  });
  server.listen(ctx.cfg.port, ctx.cfg.host, function () {
    log('info', 'listening', { url: 'http://' + ctx.cfg.host + ':' + ctx.cfg.port + '/webhook', config: describeConfig(ctx.cfg) });
  });
  return server;
}

/** Offline evaluation of a fixture file: { deal, lineItems, products }. Never touches the network. */
function evaluateFixture(file, ctx) {
  const fixture = JSON.parse(fs.readFileSync(file, 'utf8'));
  const cases = Array.isArray(fixture.cases) ? fixture.cases : [fixture];
  return cases.map(function (c) {
    const deal = margin.readDeal({ statusCode: 200, body: c.deal }).deal;
    const evaluation = margin.evaluateDeal({ deal: deal, lineItems: c.lineItems || [], products: c.products || [], rules: ctx.rules });
    return {
      case: c.name || deal.id,
      evaluation: evaluation,
      dealUpdate: margin.buildDealUpdate(evaluation, deal, ctx.rules, ctx.cfg, ctx.now()),
      approvalTask: margin.buildApprovalTask(evaluation, deal, ctx.rules, ctx.cfg, ctx.now()),
      notification: margin.buildNotification(evaluation, ctx.cfg)
    };
  });
}

async function main(argv) {
  const args = argv.slice(2);
  const flag = function (name) { const i = args.indexOf(name); return i === -1 ? null : (args[i + 1] || ''); };

  if (args.indexOf('--fixture') !== -1) {
    const env = Object.assign({}, process.env, { DRY_RUN: 'true', REQUIRE_SIGNATURE: 'false' });
    const cfg = loadConfig(env);
    const loaded = loadRules(env, cfg);
    const out = evaluateFixture(path.resolve(flag('--fixture')), { cfg: cfg, rules: loaded.rules, now: Date.now });
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    return;
  }

  if (args.indexOf('--check-rules') !== -1) {
    // Rule validation needs no secrets; it never contacts HubSpot.
    const env = Object.assign({}, process.env, { REQUIRE_SIGNATURE: 'false' });
    const checked = loadRules(env, loadConfig(env));
    process.stdout.write(JSON.stringify({ ok: true, source: checked.source, warnings: checked.warnings }, null, 2) + '\n');
    return;
  }

  const cfg = loadConfig(process.env);
  const loaded = loadRules(process.env, cfg);
  loaded.warnings.forEach(function (w) { log('warn', 'rules_warning', { warning: w }); });
  const ctx = { cfg: cfg, rules: loaded.rules, hubspot: createHubSpotClient(cfg), now: Date.now };

  if (args.indexOf('--deal') !== -1) {
    const dealId = flag('--deal');
    if (!/^\d+$/.test(dealId)) throw new Error('--deal needs a numeric HubSpot deal ID.');
    const gate = await checkPortal(ctx);
    if (!gate.allowed) throw new Error('Portal gate blocked the run: ' + gate.reason);
    const out = await validateDeal({ dealId: dealId, triggerStage: null, source: 'cli' }, ctx);
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    return;
  }
  startServer(ctx);
}

if (require.main === module) {
  main(process.argv).catch(function (err) {
    log('error', 'fatal', { error: err.message });
    process.exitCode = 1;
  });
}

module.exports = { loadRules, validateDeal, verifyRequest, evaluateFixture, checkPortal, hmacBase64, hmacHex, startServer };
