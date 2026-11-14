'use strict';

/**
 * margin.js
 *
 * Core logic of the deal line-item margin validator. It runs identically in
 * Node.js and in the n8n Code nodes (scripts/build-workflow.js embeds the
 * n8n-core:margin region verbatim). It is pure: no network, no clock, no crypto.
 * The caller passes in the time and the HMAC function.
 *
 *   verifyHubSpotV3Signature() / verifyHmacSignature()   webhook authenticity
 *   validateRules()           checks config/margin-rules*.json before anything runs
 *   extractDealEvents()       HubSpot webhook events -> deals that entered a proposal stage
 *   build*Request / read*()   deal + associated line items + product catalog reads
 *   evaluateDeal()            per-line and deal-level margin, discount, floor-price,
 *                             custom-pricing, and bundle checks
 *   buildDealUpdate()         validation properties written back to the deal
 *   buildApprovalTask()       HubSpot task for sales leadership when approval is required
 *   buildNotification()       optional chat/webhook alert (no personal data)
 *
 * Margin is computed per unit, on net price after discounts:
 *   net unit price = line amount / quantity          (falls back to price minus discount)
 *   margin %       = (net unit price - unit cost) / net unit price x 100
 *   discount %     = max(line discount %, 1 - net unit / product list price)
 * Unit cost comes from the line item's hs_cost_of_goods_sold, then the product's,
 * then (optionally) default_cost_ratio x list price. A missing cost is never guessed
 * silently: it is reported according to data_quality.missing_cost_policy.
 */

// <n8n-core:margin>
const LINE_ITEM_PROPERTIES = [
  'name', 'hs_sku', 'quantity', 'price', 'amount', 'discount', 'hs_discount_percentage',
  'hs_cost_of_goods_sold', 'hs_product_id', 'recurringbillingfrequency', 'hs_recurring_billing_period'
];
const PRODUCT_PROPERTIES = ['name', 'hs_sku', 'price', 'hs_cost_of_goods_sold'];
const DEAL_PROPERTIES = ['dealname', 'dealstage', 'pipeline', 'amount', 'deal_currency_code', 'hubspot_owner_id'];
const DEAL_PROPERTY_KEYS = ['status', 'margin_pct', 'gross_profit', 'max_discount_pct', 'violations', 'approval_required', 'checked_at', 'hash'];
const STATUS = { passed: 'passed', approval: 'approval_required', escalation: 'escalation_required', incomplete: 'incomplete_data', noItems: 'no_line_items' };
// HUBSPOT_DEFINED association: task -> deal.
const TASK_TO_DEAL_ASSOCIATION = 216;
const MARGIN_PLACEHOLDER = /^your_[a-z0-9_]+_here$/i;
const MAX_VIOLATION_TEXT = 4000;

function mBlank(value) {
  return value === undefined || value === null || (typeof value === 'string' && value.trim() === '');
}

function mNum(value) {
  if (mBlank(value)) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function mRound(value, digits) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const f = Math.pow(10, digits);
  return Math.round((value + Number.EPSILON) * f) / f;
}

function mText(value, max) {
  if (mBlank(value) || typeof value === 'object') return null;
  const text = String(value).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return text.length > max ? text.slice(0, max - 1) + '…' : text;
}

function fnv1a64(input) {
  let hash = BigInt('0xcbf29ce484222325');
  const prime = BigInt('0x100000001b3');
  const mask = BigInt('0xffffffffffffffff');
  const text = unescape(encodeURIComponent(String(input)));
  for (let i = 0; i < text.length; i++) {
    hash = hash ^ BigInt(text.charCodeAt(i));
    hash = (hash * prime) & mask;
  }
  return hash.toString(16).padStart(16, '0');
}

function constantTimeEqual(a, b) {
  const x = String(a);
  const y = String(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  return diff === 0;
}

/**
 * HubSpot signature v3: base64(HMAC-SHA256(client secret, method + uri + body + timestamp)),
 * sent as X-HubSpot-Signature-v3 with X-HubSpot-Request-Timestamp (milliseconds).
 */
function verifyHubSpotV3Signature(method, uri, rawBody, signature, timestamp, secret, nowMs, toleranceSeconds, hmacBase64) {
  if (mBlank(secret) || MARGIN_PLACEHOLDER.test(String(secret).trim())) return { ok: false, reason: 'signing_secret_not_configured' };
  if (mBlank(uri)) return { ok: false, reason: 'webhook_public_url_not_configured' };
  if (mBlank(signature) || mBlank(timestamp)) return { ok: false, reason: 'signature_headers_missing' };
  const ts = String(timestamp).trim();
  if (!/^\d{10,16}$/.test(ts)) return { ok: false, reason: 'signature_headers_malformed' };
  if (Math.abs(nowMs - Number(ts)) > toleranceSeconds * 1000) return { ok: false, reason: 'signature_timestamp_outside_tolerance' };
  const expected = hmacBase64(secret, String(method).toUpperCase() + uri + rawBody + ts);
  return constantTimeEqual(expected, String(signature).trim()) ? { ok: true, reason: null } : { ok: false, reason: 'signature_mismatch' };
}

/** Generic relay contract: X-Signature-Timestamp (seconds) + X-Signature: sha256=<hex HMAC of "<ts>.<body>">. */
function verifyHmacSignature(rawBody, signature, timestamp, secret, nowMs, toleranceSeconds, hmacHex) {
  if (mBlank(secret) || MARGIN_PLACEHOLDER.test(String(secret).trim())) return { ok: false, reason: 'signing_secret_not_configured' };
  if (mBlank(signature) || mBlank(timestamp)) return { ok: false, reason: 'signature_headers_missing' };
  const ts = String(timestamp).trim();
  const sig = String(signature).trim().replace(/^sha256=/i, '');
  if (!/^\d+$/.test(ts) || !/^[0-9a-f]{64}$/i.test(sig)) return { ok: false, reason: 'signature_headers_malformed' };
  if (Math.abs(nowMs - Number(ts) * 1000) > toleranceSeconds * 1000) return { ok: false, reason: 'signature_timestamp_outside_tolerance' };
  return constantTimeEqual(String(hmacHex(secret, ts + '.' + rawBody)).toLowerCase(), sig.toLowerCase())
    ? { ok: true, reason: null }
    : { ok: false, reason: 'signature_mismatch' };
}

function validateRules(rules) {
  const errors = [];
  const warnings = [];
  const r = rules && typeof rules === 'object' ? rules : {};
  const pct = function (v) { return typeof v === 'number' && v >= -100 && v <= 100; };
  if (r.version !== 1) errors.push('version must be 1');
  if (!/^[A-Z]{3}$/.test(String(r.currency_default || ''))) errors.push('currency_default must be a 3-letter currency code');
  const d = r.deal || {};
  ['minimum_margin_pct', 'target_margin_pct', 'escalate_below_margin_pct'].forEach(function (k) { if (!pct(d[k])) errors.push('deal.' + k + ' must be a percentage'); });
  if (!(typeof d.max_discount_pct === 'number' && d.max_discount_pct >= 0 && d.max_discount_pct <= 100)) errors.push('deal.max_discount_pct must be 0-100');
  if (pct(d.escalate_below_margin_pct) && pct(d.minimum_margin_pct) && d.escalate_below_margin_pct > d.minimum_margin_pct) {
    errors.push('deal.escalate_below_margin_pct must not exceed deal.minimum_margin_pct');
  }
  (Array.isArray(r.product_rules) ? r.product_rules : []).forEach(function (rule, i) {
    const label = 'product_rules[' + i + ']';
    const m = rule && rule.match ? rule.match : {};
    const keys = Object.keys(m);
    if (keys.length !== 1 || ['sku', 'sku_prefix', 'product_id', 'product_family'].indexOf(keys[0]) === -1 || mBlank(m[keys[0]])) {
      errors.push(label + '.match needs exactly one of sku, sku_prefix, product_id, product_family');
    }
    if (rule.min_margin_pct !== undefined && !pct(rule.min_margin_pct)) errors.push(label + '.min_margin_pct must be a percentage');
    if (rule.max_discount_pct !== undefined && !(typeof rule.max_discount_pct === 'number' && rule.max_discount_pct >= 0 && rule.max_discount_pct <= 100)) errors.push(label + '.max_discount_pct must be 0-100');
    if (rule.floor_unit_price !== undefined && !(typeof rule.floor_unit_price === 'number' && rule.floor_unit_price >= 0)) errors.push(label + '.floor_unit_price must be >= 0');
  });
  (Array.isArray(r.bundles) ? r.bundles : []).forEach(function (bundle, i) {
    const label = 'bundles[' + i + ']';
    if (mBlank(bundle && bundle.name)) errors.push(label + '.name is required');
    if (!Array.isArray(bundle.required_skus) || bundle.required_skus.length < 2) errors.push(label + '.required_skus needs at least two SKUs');
    if (bundle.min_margin_pct !== undefined && !pct(bundle.min_margin_pct)) errors.push(label + '.min_margin_pct must be a percentage');
  });
  const dq = r.data_quality || {};
  if (['flag', 'fail', 'use_default_cost_ratio'].indexOf(dq.missing_cost_policy) === -1) errors.push('data_quality.missing_cost_policy must be flag, fail, or use_default_cost_ratio');
  if (dq.missing_cost_policy === 'use_default_cost_ratio' && !(typeof dq.default_cost_ratio === 'number' && dq.default_cost_ratio > 0 && dq.default_cost_ratio < 1)) {
    errors.push('data_quality.default_cost_ratio must be between 0 and 1 when missing_cost_policy is use_default_cost_ratio');
  }
  const props = r.deal_properties || {};
  const seen = {};
  DEAL_PROPERTY_KEYS.forEach(function (k) {
    const name = props[k];
    if (!/^[a-z][a-z0-9_]{0,99}$/.test(String(name || ''))) errors.push('deal_properties.' + k + ' must be a HubSpot internal property name');
    else if (seen[name]) errors.push('deal_properties.' + k + ' reuses ' + name);
    else seen[name] = true;
  });
  const cp = r.custom_pricing || {};
  ['approved_price_property', 'product_family_property'].forEach(function (k) {
    if (!mBlank(cp[k]) && !/^[a-z][a-z0-9_]{0,99}$/.test(cp[k])) errors.push('custom_pricing.' + k + ' must be a HubSpot internal property name');
  });
  const ap = r.approval || {};
  ['approver_owner_id', 'escalation_owner_id'].forEach(function (k) {
    const v = String(ap[k] || '');
    if (MARGIN_PLACEHOLDER.test(v) || v === '') warnings.push('approval.' + k + ' is a placeholder; approval tasks are skipped until it is a numeric HubSpot owner ID');
    else if (!/^\d+$/.test(v)) errors.push('approval.' + k + ' must be a numeric HubSpot owner ID');
  });
  if (!(Number.isInteger(ap.task_due_hours) && ap.task_due_hours >= 1 && ap.task_due_hours <= 720)) errors.push('approval.task_due_hours must be 1-720');
  return { ok: errors.length === 0, errors: errors, warnings: warnings };
}

function extractDealEvents(payload, cfg) {
  const deals = {};
  const ignored = [];
  const list = Array.isArray(payload) ? payload : (payload && typeof payload === 'object' ? [payload] : []);
  list.forEach(function (e, index) {
    if (!e || typeof e !== 'object') { ignored.push({ index: index, reason: 'not_an_object' }); return; }
    const id = String(e.objectId !== undefined ? e.objectId : (e.dealId !== undefined ? e.dealId : ''));
    if (!/^\d+$/.test(id)) { ignored.push({ index: index, reason: 'deal_id_missing' }); return; }
    const type = String(e.subscriptionType || 'workflow.webhook');
    if (type !== 'deal.propertyChange' && type !== 'deal.creation' && type !== 'workflow.webhook') { ignored.push({ index: index, dealId: id, reason: 'unsupported_subscription_type:' + type }); return; }
    if (type === 'deal.propertyChange' && e.propertyName !== 'dealstage') { ignored.push({ index: index, dealId: id, reason: 'not_a_stage_change' }); return; }
    const stage = mBlank(e.propertyValue) ? (mBlank(e.dealstage) ? null : String(e.dealstage)) : String(e.propertyValue);
    if (stage !== null && cfg.proposalStageIds.indexOf(stage) === -1) { ignored.push({ index: index, dealId: id, reason: 'stage_not_monitored:' + stage }); return; }
    const occurredAt = mNum(e.occurredAt) || 0;
    if (!deals[id] || occurredAt >= deals[id].occurredAt) {
      deals[id] = { dealId: id, triggerStage: stage, occurredAt: occurredAt, eventId: mBlank(e.eventId) ? null : String(e.eventId), source: type };
    }
  });
  return { deals: Object.keys(deals).sort().map(function (k) { return deals[k]; }), ignored: ignored };
}

function dealPropertyNames(rules) {
  const p = rules.deal_properties;
  return DEAL_PROPERTIES.concat(DEAL_PROPERTY_KEYS.map(function (k) { return p[k]; }));
}

function buildDealReadRequest(dealId, rules) {
  return {
    method: 'GET',
    path: '/crm/v3/objects/deals/' + encodeURIComponent(dealId) + '?properties=' + encodeURIComponent(dealPropertyNames(rules).join(',')) + '&associations=line_items'
  };
}

function readDeal(response) {
  if (!response || Number(response.statusCode) !== 200 || !response.body) return { ok: false, status: response ? response.statusCode : 0 };
  const b = response.body;
  const p = b.properties || {};
  const assoc = b.associations && b.associations['line items'] ? b.associations['line items'] : (b.associations && b.associations.line_items ? b.associations.line_items : null);
  const ids = assoc && Array.isArray(assoc.results) ? assoc.results.map(function (r) { return String(r.id); }) : [];
  return {
    ok: true,
    deal: {
      id: String(b.id),
      name: mText(p.dealname, 200) || 'Deal ' + b.id,
      stage: mBlank(p.dealstage) ? null : String(p.dealstage),
      pipeline: mBlank(p.pipeline) ? null : String(p.pipeline),
      ownerId: mBlank(p.hubspot_owner_id) ? null : String(p.hubspot_owner_id),
      amount: mNum(p.amount),
      currency: mBlank(p.deal_currency_code) ? null : String(p.deal_currency_code).toUpperCase(),
      properties: p
    },
    lineItemIds: Array.from(new Set(ids)),
    moreLineItems: Boolean(assoc && assoc.paging && assoc.paging.next)
  };
}

function buildLineItemReadRequest(ids, rules) {
  if (!ids.length) return null;
  const extra = rules.custom_pricing && rules.custom_pricing.approved_price_property ? [rules.custom_pricing.approved_price_property] : [];
  return { method: 'POST', path: '/crm/v3/objects/line_items/batch/read', body: { properties: LINE_ITEM_PROPERTIES.concat(extra), inputs: ids.slice(0, 100).map(function (id) { return { id: id }; }) } };
}

function readBatch(response) {
  if (!response || (Number(response.statusCode) !== 200 && Number(response.statusCode) !== 207) || !response.body) return { ok: false, results: [] };
  const results = Array.isArray(response.body.results) ? response.body.results : [];
  return { ok: true, results: results.map(function (r) { return { id: String(r.id), properties: r.properties || {} }; }) };
}

function buildProductReadRequest(lineItems, rules) {
  const ids = Array.from(new Set(lineItems.map(function (li) { return li.properties.hs_product_id; }).filter(function (v) { return /^\d+$/.test(String(v || '')); }).map(String)));
  if (!ids.length) return null;
  const extra = rules.custom_pricing && rules.custom_pricing.product_family_property ? [rules.custom_pricing.product_family_property] : [];
  return { method: 'POST', path: '/crm/v3/objects/products/batch/read', body: { properties: PRODUCT_PROPERTIES.concat(extra), inputs: ids.map(function (id) { return { id: id }; }) } };
}

function matchProductRule(sku, productId, family, rules) {
  const list = Array.isArray(rules.product_rules) ? rules.product_rules : [];
  const s = sku ? String(sku).toUpperCase() : null;
  const f = family ? String(family).toLowerCase() : null;
  const by = function (kind) {
    return list.find(function (rule) {
      const m = rule.match || {};
      if (kind === 'sku') return s && m.sku && String(m.sku).toUpperCase() === s;
      if (kind === 'product_id') return productId && m.product_id && String(m.product_id) === String(productId);
      if (kind === 'sku_prefix') return s && m.sku_prefix && s.indexOf(String(m.sku_prefix).toUpperCase()) === 0;
      return f && m.product_family && String(m.product_family).toLowerCase() === f;
    }) || null;
  };
  return by('sku') || by('product_id') || by('sku_prefix') || by('product_family');
}

function evaluateLine(item, product, rules) {
  const p = item.properties;
  const pp = product ? product.properties : {};
  const dq = rules.data_quality;
  const familyProp = rules.custom_pricing && rules.custom_pricing.product_family_property;
  const approvedProp = rules.custom_pricing && rules.custom_pricing.approved_price_property;
  const sku = mText(p.hs_sku, 100) || mText(pp.hs_sku, 100);
  const quantity = mNum(p.quantity) === null ? 1 : mNum(p.quantity);
  const issues = [];
  const unitPrice = mNum(p.price) !== null ? mNum(p.price) : mNum(pp.price);
  const listPrice = mNum(pp.price) !== null ? mNum(pp.price) : unitPrice;
  let netUnit = null;
  if (quantity > 0 && mNum(p.amount) !== null) netUnit = mNum(p.amount) / quantity;
  else if (unitPrice !== null) {
    const discount = mNum(p.discount) || 0;
    const discountPct = mNum(p.hs_discount_percentage) || 0;
    netUnit = discount > 0 ? unitPrice - discount : unitPrice * (1 - discountPct / 100);
  }
  let unitCost = mNum(p.hs_cost_of_goods_sold);
  let costSource = 'line_item';
  if (unitCost === null && mNum(pp.hs_cost_of_goods_sold) !== null) { unitCost = mNum(pp.hs_cost_of_goods_sold); costSource = 'product'; }
  if (unitCost === null && dq.missing_cost_policy === 'use_default_cost_ratio' && listPrice !== null) { unitCost = listPrice * dq.default_cost_ratio; costSource = 'default_cost_ratio'; }
  if (unitCost === null) costSource = null;

  const rule = matchProductRule(sku, p.hs_product_id || null, familyProp ? pp[familyProp] : null, rules);
  const minMargin = rule && rule.min_margin_pct !== undefined ? rule.min_margin_pct : rules.deal.minimum_margin_pct;
  const maxDiscount = rule && rule.max_discount_pct !== undefined ? rule.max_discount_pct : rules.deal.max_discount_pct;
  const lineDiscountPct = mNum(p.hs_discount_percentage) || (unitPrice && mNum(p.discount) ? (mNum(p.discount) / unitPrice) * 100 : 0);
  const vsList = listPrice && netUnit !== null && listPrice > 0 ? Math.max(0, (1 - netUnit / listPrice) * 100) : 0;
  const discountPct = Math.max(lineDiscountPct, vsList);
  const approvedPrice = approvedProp ? mNum(p[approvedProp]) : null;
  const customPrice = unitPrice !== null && listPrice !== null && unitPrice < listPrice - 0.005;
  const customApproved = approvedPrice !== null && netUnit !== null && netUnit >= approvedPrice - 0.005;

  let marginPct = null;
  if (netUnit !== null && unitCost !== null) {
    marginPct = netUnit > 0 ? ((netUnit - unitCost) / netUnit) * 100 : (unitCost > 0 ? -100 : 0);
  }

  if (quantity <= 0) issues.push({ code: 'zero_quantity', severity: 'warning', detail: 'quantity is ' + quantity });
  if (!sku && dq.require_sku) issues.push({ code: 'missing_sku', severity: 'data', detail: 'line item has no SKU' });
  if (netUnit === null) issues.push({ code: 'missing_price', severity: 'data', detail: 'no price or amount' });
  if (unitCost === null) issues.push({ code: 'missing_cost', severity: dq.missing_cost_policy === 'fail' ? 'approval' : 'data', detail: 'no unit cost on line item or product' });
  if (marginPct !== null && netUnit !== null && unitCost !== null && netUnit - unitCost < 0) {
    issues.push({ code: 'negative_margin', severity: 'escalation', detail: 'margin ' + mRound(marginPct, 1) + '%' });
  } else if (marginPct !== null && marginPct < minMargin) {
    issues.push({ code: 'line_margin_below_min', severity: 'approval', detail: 'margin ' + mRound(marginPct, 1) + '% < ' + minMargin + '%' });
  }
  if (discountPct > maxDiscount + 1e-9 && !customApproved) {
    issues.push({ code: 'discount_above_max', severity: 'approval', detail: 'discount ' + mRound(discountPct, 1) + '% > ' + maxDiscount + '%' });
  }
  if (rule && rule.floor_unit_price !== undefined && netUnit !== null && netUnit < rule.floor_unit_price - 0.005) {
    issues.push({ code: 'below_floor_price', severity: 'approval', detail: 'net unit ' + mRound(netUnit, 2) + ' < floor ' + rule.floor_unit_price });
  }
  if (customPrice && !customApproved) issues.push({ code: 'custom_price_unapproved', severity: 'warning', detail: 'unit price ' + mRound(unitPrice, 2) + ' below list ' + mRound(listPrice, 2) });

  return {
    lineItemId: item.id,
    name: mText(p.name, 150) || mText(pp.name, 150) || 'Line item ' + item.id,
    sku: sku,
    productId: mBlank(p.hs_product_id) ? null : String(p.hs_product_id),
    rule: rule ? rule.label || null : null,
    quantity: quantity,
    listPrice: mRound(listPrice, 4),
    unitPrice: mRound(unitPrice, 4),
    netUnitPrice: mRound(netUnit, 4),
    unitCost: mRound(unitCost, 4),
    costSource: costSource,
    revenue: netUnit !== null && quantity > 0 ? mRound(netUnit * quantity, 2) : 0,
    cost: unitCost !== null && quantity > 0 ? mRound(unitCost * quantity, 2) : null,
    marginPct: mRound(marginPct, 2),
    discountPct: mRound(discountPct, 2),
    minMarginPct: minMargin,
    maxDiscountPct: maxDiscount,
    customPrice: customPrice,
    customPriceApproved: customApproved,
    issues: issues
  };
}

function evaluateBundles(lines, rules) {
  const out = [];
  (Array.isArray(rules.bundles) ? rules.bundles : []).forEach(function (bundle) {
    const wanted = bundle.required_skus.map(function (s) { return String(s).toUpperCase(); });
    const members = lines.filter(function (l) { return l.sku && wanted.indexOf(l.sku.toUpperCase()) !== -1; });
    const present = Array.from(new Set(members.map(function (l) { return l.sku.toUpperCase(); })));
    if (present.length !== wanted.length) return;
    const costed = members.filter(function (l) { return l.cost !== null; });
    const revenue = costed.reduce(function (s, l) { return s + l.revenue; }, 0);
    const cost = costed.reduce(function (s, l) { return s + l.cost; }, 0);
    const list = members.reduce(function (s, l) { return s + (l.listPrice || 0) * l.quantity; }, 0);
    const net = members.reduce(function (s, l) { return s + l.revenue; }, 0);
    const margin = revenue > 0 ? ((revenue - cost) / revenue) * 100 : null;
    const discount = list > 0 ? Math.max(0, (1 - net / list) * 100) : 0;
    const issues = [];
    if (costed.length === members.length && margin !== null && bundle.min_margin_pct !== undefined && margin < bundle.min_margin_pct) {
      issues.push({ code: 'bundle_margin_below_min', severity: 'approval', detail: bundle.name + ' margin ' + mRound(margin, 1) + '% < ' + bundle.min_margin_pct + '%' });
    }
    if (bundle.max_combined_discount_pct !== undefined && discount > bundle.max_combined_discount_pct + 1e-9) {
      issues.push({ code: 'bundle_discount_above_max', severity: 'approval', detail: bundle.name + ' discount ' + mRound(discount, 1) + '% > ' + bundle.max_combined_discount_pct + '%' });
    }
    out.push({ name: bundle.name, skus: present, marginPct: mRound(margin, 2), discountPct: mRound(discount, 2), issues: issues });
  });
  return out;
}

function evaluateDeal(input) {
  const rules = input.rules;
  const deal = input.deal;
  const productsById = {};
  (input.products || []).forEach(function (p) { productsById[p.id] = p; });
  const lines = (input.lineItems || []).slice().sort(function (a, b) { return Number(a.id) - Number(b.id); })
    .map(function (li) { return evaluateLine(li, productsById[String(li.properties.hs_product_id || '')] || null, rules); });
  const bundles = evaluateBundles(lines, rules);

  const costed = lines.filter(function (l) { return l.cost !== null && l.quantity > 0; });
  const revenue = lines.reduce(function (s, l) { return s + l.revenue; }, 0);
  const costedRevenue = costed.reduce(function (s, l) { return s + l.revenue; }, 0);
  const cost = costed.reduce(function (s, l) { return s + l.cost; }, 0);
  const grossProfit = costedRevenue - cost;
  const dealMargin = costedRevenue > 0 ? (grossProfit / costedRevenue) * 100 : null;
  const maxDiscount = lines.reduce(function (m, l) { return Math.max(m, l.discountPct || 0); }, 0);

  const issues = [];
  lines.forEach(function (l) { l.issues.forEach(function (i) { issues.push(Object.assign({ scope: 'line', lineItemId: l.lineItemId, sku: l.sku }, i)); }); });
  bundles.forEach(function (bn) { bn.issues.forEach(function (i) { issues.push(Object.assign({ scope: 'bundle', bundle: bn.name }, i)); }); });
  if (!lines.length) issues.push({ scope: 'deal', code: 'no_line_items', severity: 'data', detail: 'deal is in a proposal stage without line items' });
  if (dealMargin !== null && dealMargin < rules.deal.escalate_below_margin_pct) {
    issues.push({ scope: 'deal', code: 'deal_margin_below_escalation', severity: 'escalation', detail: 'deal margin ' + mRound(dealMargin, 1) + '% < ' + rules.deal.escalate_below_margin_pct + '%' });
  } else if (dealMargin !== null && dealMargin < rules.deal.minimum_margin_pct) {
    issues.push({ scope: 'deal', code: 'deal_margin_below_min', severity: 'approval', detail: 'deal margin ' + mRound(dealMargin, 1) + '% < ' + rules.deal.minimum_margin_pct + '%' });
  }
  const warnings = [];
  if (input.moreLineItems) warnings.push('more_than_100_line_items_only_first_100_evaluated');
  if (deal.currency && deal.currency !== rules.currency_default) warnings.push('deal_currency_' + deal.currency + '_differs_from_rules_currency_' + rules.currency_default);

  const has = function (sev) { return issues.some(function (i) { return i.severity === sev; }); };
  let status;
  if (!lines.length) status = STATUS.noItems;
  else if (has('escalation')) status = STATUS.escalation;
  else if (has('approval')) status = STATUS.approval;
  else if (has('data')) status = STATUS.incomplete;
  else status = STATUS.passed;

  const fingerprint = fnv1a64(JSON.stringify({
    rules: fnv1a64(JSON.stringify(rules)),
    lines: lines.map(function (l) { return [l.lineItemId, l.sku, l.quantity, l.netUnitPrice, l.unitCost, l.listPrice, l.customPriceApproved]; })
  }));

  return {
    dealId: deal.id,
    dealName: deal.name,
    status: status,
    approvalRequired: status === STATUS.approval || status === STATUS.escalation,
    escalation: status === STATUS.escalation,
    metrics: {
      revenue: mRound(revenue, 2),
      costedRevenue: mRound(costedRevenue, 2),
      cost: mRound(cost, 2),
      grossProfit: mRound(grossProfit, 2),
      marginPct: mRound(dealMargin, 2),
      targetMarginPct: rules.deal.target_margin_pct,
      minimumMarginPct: rules.deal.minimum_margin_pct,
      maxDiscountPct: mRound(maxDiscount, 2),
      costCoveragePct: lines.length ? mRound((costed.length / lines.length) * 100, 1) : null
    },
    lines: lines,
    bundles: bundles,
    issues: issues,
    warnings: warnings,
    hash: fingerprint
  };
}

function summarizeIssues(issues) {
  const text = issues.filter(function (i) { return i.severity !== 'warning'; }).map(function (i) {
    const where = i.scope === 'line' ? (i.sku || 'line ' + i.lineItemId) : (i.scope === 'bundle' ? 'bundle ' + i.bundle : 'deal');
    return '[' + i.severity.toUpperCase() + '] ' + where + ': ' + i.code + ' (' + i.detail + ')';
  }).join('\n');
  return text.length > MAX_VIOLATION_TEXT ? text.slice(0, MAX_VIOLATION_TEXT - 1) + '…' : text;
}

function buildDealUpdate(evaluation, deal, rules, cfg, nowMs) {
  const P = rules.deal_properties;
  const stored = deal.properties || {};
  if (!cfg.recheckUnchanged && stored[P.hash] === evaluation.hash && stored[P.status] === evaluation.status) {
    return { skip: true, reason: 'unchanged_since_last_validation', properties: {} };
  }
  const properties = {};
  properties[P.status] = evaluation.status;
  properties[P.margin_pct] = evaluation.metrics.marginPct === null ? '' : String(evaluation.metrics.marginPct);
  properties[P.gross_profit] = String(evaluation.metrics.grossProfit);
  properties[P.max_discount_pct] = String(evaluation.metrics.maxDiscountPct);
  properties[P.violations] = summarizeIssues(evaluation.issues);
  properties[P.approval_required] = String(evaluation.approvalRequired);
  properties[P.checked_at] = String(nowMs);
  properties[P.hash] = evaluation.hash;
  return { skip: false, reason: null, properties: properties };
}

function ownerOrNull(value) {
  const v = String(value || '').trim();
  return /^\d+$/.test(v) ? v : null;
}

function buildApprovalTask(evaluation, deal, rules, cfg, nowMs) {
  if (!evaluation.approvalRequired || !cfg.createApprovalTask) return { task: null, reason: evaluation.approvalRequired ? 'approval_tasks_disabled' : 'no_approval_required' };
  const owner = evaluation.escalation
    ? (ownerOrNull(rules.approval.escalation_owner_id) || ownerOrNull(rules.approval.approver_owner_id))
    : ownerOrNull(rules.approval.approver_owner_id);
  if (!owner) return { task: null, reason: 'approver_owner_id_not_configured' };
  const subject = (evaluation.escalation ? 'ESCALATION: ' : '') + 'Margin approval needed: ' + evaluation.dealName;
  const body = [
    'Deal margin: ' + (evaluation.metrics.marginPct === null ? 'unknown' : evaluation.metrics.marginPct + '%') +
      ' (minimum ' + rules.deal.minimum_margin_pct + '%, target ' + rules.deal.target_margin_pct + '%).',
    'Highest discount: ' + evaluation.metrics.maxDiscountPct + '%. Gross profit: ' + evaluation.metrics.grossProfit + ' ' + (deal.currency || rules.currency_default) + '.',
    '',
    summarizeIssues(evaluation.issues),
    '',
    'Approve by recording approved custom prices on the line items, or adjust pricing and move the deal back through the proposal stage.'
  ].join('\n');
  return {
    task: {
      properties: {
        hs_task_subject: mText(subject, 250),
        hs_task_body: body.slice(0, 5000),
        hs_task_status: 'NOT_STARTED',
        hs_task_priority: evaluation.escalation ? 'HIGH' : 'MEDIUM',
        hs_task_type: 'TODO',
        hs_timestamp: String(nowMs + rules.approval.task_due_hours * 3600000),
        hubspot_owner_id: owner
      },
      associationTypeId: TASK_TO_DEAL_ASSOCIATION
    },
    reason: null
  };
}

function buildNotification(evaluation, cfg) {
  if (cfg.notifyOn === 'none') return null;
  if (cfg.notifyOn === 'escalations' && !evaluation.escalation) return null;
  if (!evaluation.approvalRequired) return null;
  const head = (cfg.sandboxMode ? '[SANDBOX] ' : '') + (evaluation.escalation ? ':rotating_light: Margin escalation' : ':warning: Margin approval needed');
  const lines = evaluation.issues.filter(function (i) { return i.severity === 'approval' || i.severity === 'escalation'; }).slice(0, 8)
    .map(function (i) { return '• ' + i.code + ': ' + i.detail; });
  return {
    text: head + ' on deal ' + evaluation.dealId + ' (' + evaluation.dealName + '): margin ' + (evaluation.metrics.marginPct === null ? 'unknown' : evaluation.metrics.marginPct + '%') +
      ', max discount ' + evaluation.metrics.maxDiscountPct + '%.\n' + lines.join('\n'),
    deal_id: evaluation.dealId,
    status: evaluation.status,
    margin_pct: evaluation.metrics.marginPct,
    issue_count: evaluation.issues.length
  };
}

function buildAuditEntry(dealId, evaluation, outcome, writeMode, atIso) {
  return {
    at: atIso,
    writeMode: writeMode,
    outcome: outcome,
    dealId: dealId,
    status: evaluation ? evaluation.status : null,
    marginPct: evaluation ? evaluation.metrics.marginPct : null,
    maxDiscountPct: evaluation ? evaluation.metrics.maxDiscountPct : null,
    approvalRequired: Boolean(evaluation && evaluation.approvalRequired),
    issueCodes: evaluation ? evaluation.issues.map(function (i) { return i.code; }) : [],
    hash: evaluation ? evaluation.hash : null
  };
}
// </n8n-core:margin>

module.exports = {
  LINE_ITEM_PROPERTIES,
  PRODUCT_PROPERTIES,
  DEAL_PROPERTY_KEYS,
  STATUS,
  TASK_TO_DEAL_ASSOCIATION,
  fnv1a64,
  verifyHubSpotV3Signature,
  verifyHmacSignature,
  validateRules,
  extractDealEvents,
  buildDealReadRequest,
  readDeal,
  buildLineItemReadRequest,
  readBatch,
  buildProductReadRequest,
  matchProductRule,
  evaluateLine,
  evaluateDeal,
  summarizeIssues,
  buildDealUpdate,
  buildApprovalTask,
  buildNotification,
  buildAuditEntry
};
