'use strict';

/**
 * validate-workflow.js
 *
 * Static checks on workflow.json, run before every import:
 *   - valid JSON, unique node names and IDs, and every connection target exists
 *   - every node except the trigger is reachable from the webhook
 *   - every Code node compiles
 *   - HubSpot nodes use the hubspotAppToken credential with a placeholder ID only
 *   - every write node routes errors (continueErrorOutput / continueRegularOutput)
 *   - the workflow ships inactive
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const FILE = path.join(__dirname, '..', 'workflow.json');
const WRITE_NODES = ['Update Deal Properties', 'Create Approval Task', 'Send Leadership Notification', 'Forward Audit Log'];

function validate(workflow) {
  const errors = [];
  const nodes = Array.isArray(workflow.nodes) ? workflow.nodes : [];
  const byName = {};
  const ids = {};
  nodes.forEach(function (n) {
    if (byName[n.name]) errors.push('duplicate node name: ' + n.name);
    if (ids[n.id]) errors.push('duplicate node id: ' + n.id);
    byName[n.name] = n;
    ids[n.id] = true;
  });
  Object.keys(workflow.connections || {}).forEach(function (from) {
    if (!byName[from]) errors.push('connection from unknown node: ' + from);
    (workflow.connections[from].main || []).forEach(function (outputs) {
      (outputs || []).forEach(function (c) { if (!byName[c.node]) errors.push('connection from ' + from + ' to unknown node: ' + c.node); });
    });
  });
  const trigger = nodes.find(function (n) { return n.type === 'n8n-nodes-base.webhook'; });
  if (!trigger) errors.push('no webhook trigger');
  else {
    if (!trigger.parameters.options || trigger.parameters.options.rawBody !== true) errors.push('webhook must enable the rawBody option (signature verification needs the exact bytes)');
    if (trigger.parameters.responseMode !== 'responseNode') errors.push('webhook must use responseMode=responseNode');
    const seen = {};
    const queue = [trigger.name];
    while (queue.length) {
      const name = queue.shift();
      if (seen[name]) continue;
      seen[name] = true;
      const c = workflow.connections[name];
      if (c) (c.main || []).forEach(function (outs) { (outs || []).forEach(function (l) { queue.push(l.node); }); });
    }
    nodes.forEach(function (n) { if (!seen[n.name]) errors.push('unreachable node: ' + n.name); });
  }
  nodes.forEach(function (n) {
    if (n.type === 'n8n-nodes-base.code') {
      try { new vm.Script('(async function () {\n' + n.parameters.jsCode + '\n})'); } catch (err) { errors.push('Code node "' + n.name + '" does not compile: ' + err.message); }
    }
    if (n.type === 'n8n-nodes-base.httpRequest' && n.parameters.nodeCredentialType === 'hubspotAppToken') {
      const cred = n.credentials && n.credentials.hubspotAppToken;
      if (!cred || !/^your_[a-z0-9_]+_here$/.test(cred.id)) errors.push('HubSpot node "' + n.name + '" must reference a placeholder credential ID');
    }
    if (n.credentials) {
      Object.keys(n.credentials).forEach(function (k) {
        if (!/^your_[a-z0-9_]+_here$/.test(String(n.credentials[k].id))) errors.push('node "' + n.name + '" credential ' + k + ' is not a placeholder');
      });
    }
  });
  WRITE_NODES.forEach(function (name) {
    const n = byName[name];
    if (!n) errors.push('missing write node: ' + name);
    else if (n.onError !== 'continueErrorOutput' && n.onError !== 'continueRegularOutput') errors.push('write node "' + name + '" must route errors');
  });
  if (workflow.active !== false) errors.push('workflow must ship inactive');
  return { ok: errors.length === 0, errors: errors, nodeCount: nodes.length };
}

if (require.main === module) {
  const result = validate(JSON.parse(fs.readFileSync(FILE, 'utf8')));
  if (!result.ok) {
    process.stderr.write('workflow.json failed validation:\n  - ' + result.errors.join('\n  - ') + '\n');
    process.exit(1);
  }
  process.stdout.write('workflow.json is valid (' + result.nodeCount + ' nodes).\n');
}

module.exports = { validate };
