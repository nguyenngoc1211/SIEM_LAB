const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const workflowPath = path.resolve(__dirname, '..', 'integrations', 'n8n', 'mitre-mapping-webhook.workflow.json');
const workflow = JSON.parse(fs.readFileSync(workflowPath, 'utf8'));
const nodes = Object.fromEntries(workflow.nodes.map((node) => [node.name, node]));

assert.equal(workflow.id, 'socAlertGeminiV1');
assert.equal(workflow.nodes.length, 8);

function runCode(name, inputJson, previous = {}) {
  const source = nodes[name]?.parameters?.jsCode;
  assert.equal(typeof source, 'string', `${name} must contain jsCode`);
  const fn = new Function('$input', '$', '$execution', source);
  const $input = {
    first: () => ({ json: inputJson }),
    all: () => [{ json: inputJson }],
  };
  const selector = (nodeName) => ({
    first: () => ({ json: previous[nodeName] ?? {} }),
  });
  const result = fn($input, selector, { id: 'test-execution' });
  assert.ok(Array.isArray(result) && result.length === 1, `${name} must return one n8n item`);
  return result[0].json;
}

for (const node of workflow.nodes.filter((item) => item.type === 'n8n-nodes-base.code')) {
  assert.doesNotThrow(() => new Function('$input', '$', '$execution', node.parameters.jsCode), `${node.name} syntax`);
}

const webhookInput = {
  body: {
    _source: {
      id: 'wazuh-alert-1',
      timestamp: '2026-08-04T10:00:00+07:00',
      rule: { level: 7, description: 'ET SCAN Suspicious inbound traffic' },
      data: {
        src_ip: '192.168.56.100',
        src_port: 4444,
        dest_ip: '192.168.56.10',
        dest_port: 80,
        flow_id: '123456',
        alert: {
          signature: 'ET SCAN Suspicious inbound traffic',
          category: 'Attempted Information Leak',
          severity: 1,
          metadata: { tag: ['scan'] },
        },
      },
    },
  },
};

const normalized = runCode('Normalize Alert', webhookInput);
assert.equal(normalized.alert_context.signature, 'ET SCAN Suspicious inbound traffic');
assert.equal(normalized.alert_context.source_port, 4444);
assert.equal(normalized.mapper_input._source.id, 'wazuh-alert-1');

const mapping = {
  mapping_status: 'mapped',
  primary_mapping: { technique_id: 'T1595', name: 'Active Scanning', confidence: 0.98 },
  supporting_evidence: [{ field: 'event.action', value: 'scan' }],
  contradictory_evidence: [],
  alternative_candidates: [],
  pipeline: { attack_index_version: '1.0.0', degraded_modes: [] },
};

const prepared = runCode('Prepare Gemini Request', mapping, { 'Normalize Alert': normalized });
const prompt = prepared.gemini_request.contents[0].parts[0].text;
assert.match(prompt, /senior SOC incident response analyst/);
assert.match(prompt, /T1595/);
assert.doesNotMatch(prompt, /[À-ɏ]/u, 'Gemini prompt instructions must be written in English');
assert.equal(prepared.gemini_request.generationConfig.responseMimeType, 'application/json');

const geminiResponse = {
  candidates: [{
    finishReason: 'STOP',
    content: { parts: [{ text: JSON.stringify({
      summary: 'Phát hiện hoạt động quét chủ động vào máy chủ web.',
      is_false_positive: false,
      threat_level: 'High',
      confidence: 'High',
      attack_likelihood: 'High',
      rationale: 'Chữ ký và bằng chứng mapping phù hợp với hoạt động quét.',
      observed_evidence: ['Chữ ký IDS chứa hành vi scan.'],
      recommended_actions: ['Xác minh địa chỉ nguồn và phạm vi quét.'],
      need_admin_verification: true,
      soar_action: 'create_incident',
      analyst_notes: 'Chưa có bằng chứng khai thác thành công.',
    }) }] },
  }],
  modelVersion: 'gemini-2.5-flash-test',
  responseId: 'response-test',
  usageMetadata: { totalTokenCount: 100 },
};

const parsed = runCode('Parse Gemini Analysis', geminiResponse);
assert.equal(parsed.llm_meta.ok, true);
assert.equal(parsed.analysis.threat_level, 'High');

const analystAlert = runCode('Build Analyst Alert', parsed, {
  'Normalize Alert': normalized,
  'Map to ATT&CK': mapping,
});
assert.equal(analystAlert.attack_mapping.primary_mapping.technique_id, 'T1595');
assert.equal(analystAlert.decision.action_executed, false);
assert.match(analystAlert.analyst_message, /T1595/);

const blocked = runCode('Parse Gemini Analysis', { promptFeedback: { blockReason: 'SAFETY' } });
assert.equal(blocked.llm_meta.ok, false);
assert.equal(blocked.analysis.need_admin_verification, true);
assert.ok(blocked.llm_meta.errors.length >= 2);

console.log(`n8n workflow test passed: ${workflow.nodes.length} nodes, 4 Code nodes, success and Gemini-block fallback paths.`);
