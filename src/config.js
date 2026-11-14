'use strict';

/**
 * config.js
 *
 * Environment loader and safety gates for the margin validator.
 *
 * Fail-safe defaults (blank or "your_..._here" placeholder values count as unset):
 *
 *   DRY_RUN=true            Evaluate every deal and return the full verdict; write
 *                           nothing (no deal properties, no tasks, no notifications).
 *   SANDBOX_MODE=true       Use HubSpot only after the portal is verified as a
 *                           SANDBOX or DEVELOPER_TEST account; notifications go to
 *                           SANDBOX_NOTIFICATION_WEBHOOK_URL.
 *   REQUIRE_SIGNATURE=true  Reject webhooks without a valid signature.
 *
 * SANDBOX_MODE=false also requires ALLOW_PRODUCTION_MODE=true. Only the literal
 * string "false" turns a safety flag off.
 *
 * The n8n-core:config region is embedded verbatim into the n8n Code nodes by
 * scripts/build-workflow.js, so it stays dependency-free.
 */

// <n8n-core:config>
const CONFIG_KEYS = [
  'DRY_RUN',
  'SANDBOX_MODE',
  'ALLOW_PRODUCTION_MODE',
  'REQUIRE_SIGNATURE',
  'SIGNATURE_MODE',
  'SIGNATURE_TOLERANCE_SECONDS',
  'WEBHOOK_PUBLIC_URL',
  'HUBSPOT_BASE_URL',
  'HUBSPOT_SANDBOX_PORTAL_ID',
  'PROPOSAL_STAGE_IDS',
  'PIPELINE_IDS',
  'CREATE_APPROVAL_TASK',
  'NOTIFY_ON',
  'RECHECK_UNCHANGED'
];

const SANDBOX_ACCOUNT_TYPES = ['SANDBOX', 'DEVELOPER_TEST'];
const PLACEHOLDER_PATTERN = /^your_[a-z0-9_]+_here$/i;

function cfgUnset(value) {
  if (value === undefined || value === null) return true;
  const text = String(value).trim();
  return text === '' || PLACEHOLDER_PATTERN.test(text);
}

function safetyFlag(value) {
  if (cfgUnset(value)) return true;
  return String(value).trim().toLowerCase() !== 'false';
}

function optInFlag(value) {
  if (cfgUnset(value)) return false;
  return String(value).trim().toLowerCase() === 'true';
}

function boundedInt(value, fallback, min, max, name) {
  if (cfgUnset(value)) return fallback;
  const parsed = Number(String(value).trim());
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(name + ' must be an integer between ' + min + ' and ' + max + ' (received "' + value + '").');
  }
  return parsed;
}

function idList(value, fallback, name) {
  const source = cfgUnset(value) ? fallback : String(value);
  return source.split(',').map(function (v) { return v.trim(); }).filter(Boolean).map(function (v) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(v)) throw new Error(name + ' may only contain HubSpot IDs (letters, digits, "-", "_").');
    return v;
  });
}

function parseConfig(env) {
  const e = env || {};
  const dryRun = safetyFlag(e.DRY_RUN);
  const sandboxMode = safetyFlag(e.SANDBOX_MODE);
  const allowProductionMode = optInFlag(e.ALLOW_PRODUCTION_MODE);
  if (!sandboxMode && !allowProductionMode) {
    throw new Error(
      'Refusing to start: SANDBOX_MODE=false writes validation results and approval tasks to production deals. ' +
      'Set ALLOW_PRODUCTION_MODE=true only after validating your margin rules in a HubSpot sandbox.'
    );
  }

  const baseUrl = (cfgUnset(e.HUBSPOT_BASE_URL) ? 'https://api.hubapi.com' : String(e.HUBSPOT_BASE_URL).trim()).replace(/\/+$/, '');
  if (!/^https:\/\//i.test(baseUrl)) throw new Error('HUBSPOT_BASE_URL must use https://.');
  const portal = cfgUnset(e.HUBSPOT_SANDBOX_PORTAL_ID) ? null : String(e.HUBSPOT_SANDBOX_PORTAL_ID).trim();
  if (portal && !/^\d+$/.test(portal)) throw new Error('HUBSPOT_SANDBOX_PORTAL_ID must be numeric.');

  const signatureMode = cfgUnset(e.SIGNATURE_MODE) ? 'hubspot_v3' : String(e.SIGNATURE_MODE).trim().toLowerCase();
  if (signatureMode !== 'hubspot_v3' && signatureMode !== 'hmac_sha256') throw new Error('SIGNATURE_MODE must be "hubspot_v3" or "hmac_sha256".');
  const publicUrl = cfgUnset(e.WEBHOOK_PUBLIC_URL) ? null : String(e.WEBHOOK_PUBLIC_URL).trim();
  if (publicUrl && !/^https:\/\//i.test(publicUrl)) throw new Error('WEBHOOK_PUBLIC_URL must be the exact https:// URL HubSpot calls.');

  const notifyOn = cfgUnset(e.NOTIFY_ON) ? 'violations' : String(e.NOTIFY_ON).trim().toLowerCase();
  if (['violations', 'escalations', 'none'].indexOf(notifyOn) === -1) throw new Error('NOTIFY_ON must be "violations", "escalations", or "none".');

  const writeMode = dryRun ? 'dry_run' : (sandboxMode ? 'sandbox' : 'production');
  return {
    dryRun: dryRun,
    sandboxMode: sandboxMode,
    allowProductionMode: allowProductionMode,
    writeMode: writeMode,
    writesEnabled: writeMode !== 'dry_run',
    requireSignature: safetyFlag(e.REQUIRE_SIGNATURE),
    signatureMode: signatureMode,
    signatureToleranceSeconds: boundedInt(e.SIGNATURE_TOLERANCE_SECONDS, 300, 30, 900, 'SIGNATURE_TOLERANCE_SECONDS'),
    webhookPublicUrl: publicUrl,
    hubspotBaseUrl: baseUrl,
    sandboxPortalId: portal,
    proposalStageIds: idList(e.PROPOSAL_STAGE_IDS, 'decisionmakerboughtin,contractsent', 'PROPOSAL_STAGE_IDS'),
    pipelineIds: idList(e.PIPELINE_IDS, '', 'PIPELINE_IDS'),
    createApprovalTask: safetyFlag(e.CREATE_APPROVAL_TASK),
    notifyOn: notifyOn,
    recheckUnchanged: optInFlag(e.RECHECK_UNCHANGED)
  };
}

function evaluateHubSpotTarget(cfg, account) {
  if (!cfg) return { allowed: false, reason: 'missing_config' };
  if (!cfg.sandboxMode) {
    return cfg.allowProductionMode
      ? { allowed: true, reason: 'production_mode_explicitly_allowed' }
      : { allowed: false, reason: 'production_mode_not_allowed' };
  }
  const type = String((account && account.accountType) || '').toUpperCase();
  if (SANDBOX_ACCOUNT_TYPES.indexOf(type) === -1) {
    return { allowed: false, reason: 'sandbox_mode_requires_sandbox_or_developer_test_portal (received "' + (type || 'unknown') + '")' };
  }
  if (cfg.sandboxPortalId && String(account.portalId) !== cfg.sandboxPortalId) {
    return { allowed: false, reason: 'sandbox_portal_id_mismatch' };
  }
  return { allowed: true, reason: 'sandbox_portal_verified' };
}
// </n8n-core:config>

/** Full runtime config for the standalone engine, including secrets. */
function loadConfig(env) {
  const source = env || process.env;
  const settings = parseConfig(source);
  const secret = function (name) { return cfgUnset(source[name]) ? null : String(source[name]).trim(); };
  const cfg = Object.assign({}, settings, {
    hubspotPrivateAppToken: secret('HUBSPOT_PRIVATE_APP_TOKEN'),
    webhookSigningSecret: secret('WEBHOOK_SIGNING_SECRET'),
    marginRulesFile: secret('MARGIN_RULES_FILE'),
    notificationWebhookUrl: secret('NOTIFICATION_WEBHOOK_URL'),
    sandboxNotificationWebhookUrl: secret('SANDBOX_NOTIFICATION_WEBHOOK_URL'),
    auditLogWebhookUrl: secret('AUDIT_LOG_WEBHOOK_URL'),
    host: secret('HOST') || '127.0.0.1',
    port: boundedInt(source.PORT, 8792, 1, 65535, 'PORT')
  });
  if (cfg.requireSignature && !cfg.webhookSigningSecret) {
    throw new Error('REQUIRE_SIGNATURE is on (the default) but WEBHOOK_SIGNING_SECRET is blank or a placeholder.');
  }
  if (cfg.requireSignature && cfg.signatureMode === 'hubspot_v3' && !cfg.webhookPublicUrl) {
    throw new Error('SIGNATURE_MODE=hubspot_v3 needs WEBHOOK_PUBLIC_URL (the exact URL HubSpot calls) to verify signatures.');
  }
  ['notificationWebhookUrl', 'sandboxNotificationWebhookUrl', 'auditLogWebhookUrl'].forEach(function (key) {
    if (cfg[key] && !/^https:\/\//i.test(cfg[key])) throw new Error(key + ' must use https://.');
  });
  return Object.freeze(cfg);
}

function describeConfig(cfg) {
  const view = Object.assign({}, cfg);
  ['hubspotPrivateAppToken', 'webhookSigningSecret', 'notificationWebhookUrl', 'sandboxNotificationWebhookUrl', 'auditLogWebhookUrl'].forEach(function (key) {
    if (key in view) view[key] = view[key] ? '[redacted]' : null;
  });
  return view;
}

module.exports = {
  CONFIG_KEYS,
  SANDBOX_ACCOUNT_TYPES,
  PLACEHOLDER_PATTERN,
  cfgUnset,
  safetyFlag,
  optInFlag,
  parseConfig,
  evaluateHubSpotTarget,
  loadConfig,
  describeConfig
};
