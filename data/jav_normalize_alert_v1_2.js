// Updated 27/09/2026: refine T1071.001 web requests, DoS actions, and scenario vocabulary.
// Updated 01/10/2026: normalize Wazuh and Suricata severity, then select the higher score.

function toInt(value) {
  if (value === null || value === undefined) return null;
  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? null : parsed;
}

function normalizeWazuhSeverity(level) {
  if (level === null) return null;
  if (level >= 13) return 4;
  if (level >= 10) return 3;
  if (level >= 7) return 2;
  if (level >= 4) return 1;
  return 0;
}

function normalizeSuricataSeverity(severity) {
  if (severity === null) return null;
  if (severity <= 1) return 3;
  if (severity === 2) return 2;
  if (severity === 3) return 1;
  return 0;
}

function safeDecode(value) {
  if (!value) return null;

  try {
    return decodeURIComponent(String(value).replace(/\+/g, "%20"));
  } catch (e) {
    return String(value);
  }
}

function cleanText(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/[_]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined || value === "") return [];
  return [value];
}

const BEHAVIOR_PATTERNS = {
  authentication: [
    /\blogin\b/i,
    /\blogon\b/i,
    /\bauth(?:entication|enticate)?\b/i,
    /\bcredential(?:s)?\b/i,
    /\bpassword\b/i
  ],
  login: [/\blogin\b/i, /\blogon\b/i, /\bsign[\s_-]*in\b/i],
  scan: [
    /\bscan(?:ning|ner)?\b/i,
    /\bprobe\b/i,
    /\bsweep\b/i,
    /\benumerat(?:e|ed|ion)\b/i,
    /\bassessment\b/i,
    /\b(?:exposure|capability)[\s_-]*check\b/i,
    /\bservice[\s_-]*banner[\s_-]*(?:identification|probe|check)\b/i,
    /\breconnaissance\b/i,
    /\bnmap\b/i,
    /\bmasscan\b/i
  ],
  probe: [
    /\bprobe\b/i,
    /\bfingerprint(?:ing)?\b/i,
    /\bbanner[\s_-]*grab\b/i,
    /\bservice[\s_-]*banner[\s_-]*identification\b/i
  ],
  discover: [/\bdiscover(?:y)?\b/i, /\benumerat(?:e|ed|ion)\b/i],
  exploit: [
    /\bexploit(?:ation)?\b/i,
    /\bsql[\s_-]*injection\b/i,
    /\bsqli\b/i,
    /\bxss\b/i,
    /\bcross[\s_-]*site[\s_-]*scripting\b/i,
    /\bcommand[\s_-]*injection\b/i,
    /\bpath[\s_-]*traversal\b/i,
    /\bdirectory[\s_-]*traversal\b/i,
    /\bremote[\s_-]*code[\s_-]*execution\b/i,
    /\brce\b/i,
    /\bdeseriali[sz]ation\b/i,
    /\bauth(?:entication)?[\s_-]*bypass\b/i
  ],
  tunnel: [
    /\btunnel(?:ing|ed)?\b/i,
    /\bencapsulat(?:e|ed|ion)\b/i,
    /\bport[\s_-]*forward(?:ing)?\b/i
  ],
  webRequest: [
    /\bhttps?[\s_-]*(?:c2|beacon)\b/i,
    /\bweb[\s_-]*(?:protocol[\s_-]*c2|beacon)\b/i,
    /\bcommand[\s_-]*and[\s_-]*control[\s_-]*over[\s_-]*https?\b/i,
    /\bperiodic[\s_-]*web[\s_-]*(?:telemetry|checkin|heartbeat|sync|tasks?)(?:[\s_-]*traffic)?\b/i
  ],
  flood: [
    /\bflood\b/i,
    /\bdos\b/i,
    /\bddos\b/i,
    /\bdenial[\s_-]*of[\s_-]*service\b/i,
    /\bamplification\b/i,
    /\bexhaustion\b/i,
    /\brequest[\s_-]*(?:burst|surge)\b/i,
    /\bhigh[\s_-]*rate\b/i,
    /\brepeated[\s_-]+(?:aggregation[\s_-]+)?submissions?\b/i
  ],
  dataTransfer: [
    /\bdata[\s_-]*transfer\b/i,
    /\bexfiltrat(?:e|ed|ion)\b/i,
    /\bupload(?:ed|ing)?\b/i,
    /\bdownload(?:ed|ing)?\b/i
  ],
  connect: [
    /\bconnect(?:ed|ion|ing)?\b/i,
    /\bservice[\s_-]*access\b/i,
    /\bsession[\s_-]*(?:open|establish)/i
  ]
};

const BEHAVIOR_PRIORITY = [
  "authentication",
  "network_scan",
  "web_exploit",
  "tunneling",
  "flood",
  "data_transfer",
  "web_request",
  "service_access",
  "network_communication"
];

function countMatches(text, patterns) {
  if (!text) return 0;
  return patterns.reduce(
    (score, regex) => score + (regex.test(text) ? 1 : 0),
    0
  );
}

function addPatternScore(scores, key, text, patterns, weight) {
  scores[key] += countMatches(text, patterns) * weight;
}

function pickWinner(scores, minimumScore) {
  let winner = "unknown";
  let winnerScore = minimumScore - 1;

  for (const key of BEHAVIOR_PRIORITY) {
    if (scores[key] > winnerScore) {
      winner = key;
      winnerScore = scores[key];
    }
  }

  return winner;
}

function inferBehavior(data, alert, http, tags, path, ruleName) {
  const signatureText = cleanText(ruleName).toLowerCase();
  const categoryText = cleanText(alert.category).toLowerCase();
  const tagText = tags.map(cleanText).join(" ").toLowerCase();
  const userAgentText = cleanText(http.http_user_agent).toLowerCase();
  const appProtocol = normalizeApplicationProtocol(data.app_proto);
  const httpMethod = cleanText(http.http_method);

  const scores = {
    authentication: 0,
    network_scan: 0,
    web_exploit: 0,
    tunneling: 0,
    flood: 0,
    data_transfer: 0,
    web_request: 0,
    service_access: 0,
    network_communication: 0
  };

  // Rule/signature is a strong signal, category is a weak hint, and tags are
  // structured sensor evidence. No individual Suricata rule is hard-coded.
  addPatternScore(scores, "authentication", signatureText, BEHAVIOR_PATTERNS.authentication, 2);
  addPatternScore(scores, "authentication", categoryText, BEHAVIOR_PATTERNS.authentication, 1);
  addPatternScore(scores, "authentication", tagText, BEHAVIOR_PATTERNS.authentication, 2);

  addPatternScore(scores, "network_scan", signatureText, BEHAVIOR_PATTERNS.scan, 3);
  addPatternScore(scores, "network_scan", categoryText, BEHAVIOR_PATTERNS.scan, 1);
  addPatternScore(scores, "network_scan", tagText, BEHAVIOR_PATTERNS.scan, 2);
  addPatternScore(scores, "network_scan", userAgentText, BEHAVIOR_PATTERNS.scan, 2);

  addPatternScore(scores, "web_exploit", signatureText, BEHAVIOR_PATTERNS.exploit, 3);
  addPatternScore(scores, "web_exploit", categoryText, BEHAVIOR_PATTERNS.exploit, 1);
  addPatternScore(scores, "web_exploit", tagText, BEHAVIOR_PATTERNS.exploit, 3);

  addPatternScore(scores, "tunneling", signatureText, BEHAVIOR_PATTERNS.tunnel, 3);
  addPatternScore(scores, "tunneling", categoryText, BEHAVIOR_PATTERNS.tunnel, 1);
  addPatternScore(scores, "tunneling", tagText, BEHAVIOR_PATTERNS.tunnel, 2);

  addPatternScore(scores, "flood", signatureText, BEHAVIOR_PATTERNS.flood, 3);
  addPatternScore(scores, "flood", categoryText, BEHAVIOR_PATTERNS.flood, 1);
  addPatternScore(scores, "flood", tagText, BEHAVIOR_PATTERNS.flood, 2);

  addPatternScore(scores, "data_transfer", signatureText, BEHAVIOR_PATTERNS.dataTransfer, 3);
  addPatternScore(scores, "data_transfer", categoryText, BEHAVIOR_PATTERNS.dataTransfer, 1);
  addPatternScore(scores, "data_transfer", tagText, BEHAVIOR_PATTERNS.dataTransfer, 2);

  addPatternScore(scores, "web_request", signatureText, BEHAVIOR_PATTERNS.webRequest, 3);
  addPatternScore(scores, "web_request", categoryText, BEHAVIOR_PATTERNS.webRequest, 1);
  addPatternScore(scores, "web_request", tagText, BEHAVIOR_PATTERNS.webRequest, 2);

  if (path && /\/(?:login|signin|auth|session)(?:\/|$)/i.test(path)) {
    scores.authentication += 2;
  }

  const status = toInt(http.status);
  if ([401, 403].includes(status)) scores.authentication += 1;

  if (/^web application attack$/i.test(cleanText(alert.category))) {
    scores.web_exploit += 1;
  }

  // Structured observables provide baseline event semantics without deciding
  // an ATT&CK technique. Strong behavior terms above can outvote these hints.
  const hasHttpSemantics = appProtocol === "http" || Boolean(httpMethod || path);
  if (appProtocol === "http") scores.web_request += 1;
  if (httpMethod || path) scores.web_request += 2;

  if (appProtocol !== "unknown" && appProtocol !== "http") {
    scores.service_access += 2;
  }

  if (data.proto) scores.network_communication += 1;
  if (data.direction || data.flow_id) scores.network_communication += 1;

  const behavior = pickWinner(scores, 2);
  let eventType = "unknown";
  let eventAction = "unknown";

  if (behavior === "authentication") {
    eventType = "authentication";
    eventAction = countMatches(signatureText, BEHAVIOR_PATTERNS.login) > 0 ||
      (path && /\/(?:login|signin)(?:\/|$)/i.test(path))
      ? "login"
      : "authenticate";
  } else if (behavior === "network_scan") {
    eventType = "network_scan";
    if (countMatches(signatureText, BEHAVIOR_PATTERNS.probe) > 0) {
      eventAction = "probe";
    } else if (countMatches(signatureText, BEHAVIOR_PATTERNS.discover) > 0) {
      eventAction = "discover";
    } else {
      eventAction = "scan";
    }
  } else if (behavior === "web_exploit") {
    eventType = "web_request";
    eventAction = "exploit";
  } else if (behavior === "tunneling") {
    eventType = "network_communication";
    eventAction = "tunnel";
  } else if (behavior === "flood") {
    eventType = hasHttpSemantics ? "web_request" : "network_communication";
    eventAction = "flood";
  } else if (behavior === "data_transfer") {
    eventType = "data_transfer";
  } else if (behavior === "web_request") {
    eventType = "web_request";
  } else if (behavior === "service_access") {
    eventType = "service_access";
    eventAction = countMatches(signatureText, BEHAVIOR_PATTERNS.connect) > 0
      ? "connect"
      : "unknown";
  } else if (behavior === "network_communication") {
    eventType = "network_communication";
    eventAction = countMatches(signatureText, BEHAVIOR_PATTERNS.connect) > 0
      ? "connect"
      : "unknown";
  }

  return { behavior, eventType, eventAction, scores };
}

function inferOutcome(eventType, status) {
  if (status === null) return "unknown";

  if (eventType === "authentication" && [401, 403].includes(status)) {
    return "failure";
  }

  // A 2xx response proves only that HTTP completed; it does not prove that an
  // authentication or exploitation attempt succeeded.
  return "unknown";
}

function normalizeApplicationProtocol(value) {
  if (value === null || value === undefined || value === "") return "unknown";
  const normalized = String(value).trim().toLowerCase();
  if (!normalized || normalized === "failed") return "unknown";

  // Keep compatibility with the current evidence vocabulary.
  if (normalized === "llmnr") return "llmr";
  return normalized;
}

function inferTargetType(data, flow, http, metadata, applicationProtocol) {
  if (data.user || data.username || http.username) return "account";
  if (
    http.hostname ||
    applicationProtocol !== "unknown" ||
    asArray(metadata.attack_target).some(value =>
      /^web[\s_-]*server$/i.test(String(value))
    )
  ) {
    return "application";
  }
  if (data.dest_ip || data.dest_port || flow.dest_ip || flow.dest_port) return "host";
  return "unknown";
}

function buildRetrievalText(fields) {
  const valueOrUnknown = value =>
    value === null || value === undefined || String(value).trim() === ""
      ? "unknown"
      : String(value).trim();

  return [
    `Rule: ${valueOrUnknown(fields.rule)}`,
    `Event type: ${valueOrUnknown(fields.eventType)}`,
    `Action: ${valueOrUnknown(fields.eventAction)}`,
    `Outcome: ${valueOrUnknown(fields.outcome)}`,
    `Category: ${valueOrUnknown(fields.category)}`,
    `Target type: ${valueOrUnknown(fields.targetType)}`,
    `Transport protocol: ${valueOrUnknown(fields.transportProtocol)}`,
    `Application protocol: ${valueOrUnknown(fields.applicationProtocol)}`,
    `Flow direction: ${valueOrUnknown(fields.flowDirection)}`,
    `HTTP method: ${valueOrUnknown(fields.httpMethod)}`,
    `HTTP status: ${valueOrUnknown(fields.httpStatus)}`
  ].join("\n");
}

function normalizeWazuhAlert(src) {
  const data = src.data || {};
  const alert = data.alert || {};
  const http = data.http || {};
  const flow = data.flow || {};
  const wazuhRule = src.rule || {};
  const metadata = alert.metadata || {};
  const tags = asArray(metadata.tag);
  const groups = asArray(wazuhRule.groups);

  const url = http.url || null;

  let path = null;
  let query = null;
  let queryDecoded = null;

  if (url) {
    const idx = url.indexOf("?");

    if (idx >= 0) {
      path = url.slice(0, idx);
      query = url.slice(idx + 1);
    } else {
      path = url;
      query = null;
    }

    queryDecoded = query ? safeDecode(query) : null;
  }

  const dataSourceCategory = "network_traffic";
  const dataSubcategory = "network_ids";
  const applicationProtocol = normalizeApplicationProtocol(data.app_proto);
  const transportProtocol = data.proto
    ? String(data.proto).trim().toLowerCase()
    : "unknown";
  const flowDirection = data.direction || "unknown";
  const ruleName = alert.signature || wazuhRule.description || null;
  const httpMethod = http.http_method
    ? String(http.http_method).trim().toUpperCase()
    : null;
  const httpStatus = toInt(http.status);
  const behavior = inferBehavior(data, alert, http, tags, path, ruleName);
  const eventType = behavior.eventType;
  const eventAction = behavior.eventAction;
  const outcome = inferOutcome(eventType, httpStatus);

  const disposition = alert.action || "unknown";

  const level = toInt(wazuhRule.level);
  const suricataSeverity = toInt(alert.severity);
  const wazuhSeverityScore = normalizeWazuhSeverity(level);
  const suricataSeverityScore = normalizeSuricataSeverity(suricataSeverity);
  const availableSeverityScores = [wazuhSeverityScore, suricataSeverityScore]
    .filter(score => score !== null);
  const normalizedSeverity = availableSeverityScores.length
    ? Math.max(...availableSeverityScores)
    : null;

  let normalizationSource = null;
  let severitySourceValue = null;
  let severitySourceScale = null;

  if (normalizedSeverity !== null) {
    const scoresTie =
      wazuhSeverityScore !== null &&
      suricataSeverityScore !== null &&
      wazuhSeverityScore === suricataSeverityScore;

    if (scoresTie) {
      normalizationSource = "wazuh_level+suricata_severity";
    } else if (
      suricataSeverityScore !== null &&
      (wazuhSeverityScore === null || suricataSeverityScore > wazuhSeverityScore)
    ) {
      normalizationSource = "suricata_severity";
    } else {
      normalizationSource = "wazuh_level";
    }

    if (normalizationSource === "suricata_severity") {
      severitySourceValue = suricataSeverity;
      severitySourceScale = "suricata_severity";
    } else {
      // On an equal normalized score, retain Wazuh as the scalar source value
      // while normalization_source records that both sources agreed.
      severitySourceValue = level;
      severitySourceScale = "wazuh_level";
    }
  }

  const targetType = inferTargetType(
    data,
    flow,
    http,
    metadata,
    applicationProtocol
  );
  const retrievalText = buildRetrievalText({
    rule: ruleName,
    eventType,
    eventAction,
    outcome,
    category: dataSourceCategory,
    targetType,
    transportProtocol,
    applicationProtocol,
    flowDirection,
    httpMethod,
    httpStatus
  });

  return {
    schema_version: "1.2",
    alert_id:
      src.id ||
      `wazuh-${src._id || data.flow_id || data.tx_id || Date.now()}`,

    event_time: data.timestamp || src.timestamp || null,

    producer: {
      type: "nids",
      name:
        (src.location || "").includes("suricata") ||
        groups.includes("suricata")
          ? "suricata"
          : "wazuh",
      rule_id:
        alert.signature_id !== undefined && alert.signature_id !== null
          ? String(alert.signature_id)
          : null,
      rule_name: ruleName
    },

    data_source: {
      category: dataSourceCategory,
      subcategory: dataSubcategory
    },

    event: {
      type: eventType,
      action: eventAction,
      outcome: outcome,
      disposition: disposition
    },

    source: {
      type: "host",
      ip: data.src_ip || flow.src_ip || null,
      port: toInt(data.src_port || flow.src_port),
      hostname: null,
      user: null,
      process: null
    },

    target: {
      type: targetType,
      ip: data.dest_ip || flow.dest_ip || null,
      port: toInt(data.dest_port || flow.dest_port),
      hostname: http.hostname || null,
      resource: path || null
    },

    severity: {
      source_value: severitySourceValue,
      source_scale: severitySourceScale,
      suricata: suricataSeverity,
      wazuh_level: level,
      normalized: normalizedSeverity,
      normalization_source: normalizationSource
    },

    network: {
      transport_protocol: transportProtocol,
      application_protocol: applicationProtocol,
      direction: flowDirection,
      flow_direction: flowDirection,
      zone_direction: "unknown",
      flow_id: data.flow_id || null,
      interface: data.in_iface || null,
      packet_source: data.pkt_src || null,
      packets_to_target: toInt(flow.pkts_toserver),
      packets_to_source: toInt(flow.pkts_toclient),
      bytes_to_target: toInt(flow.bytes_toserver),
      bytes_to_source: toInt(flow.bytes_toclient),
      flow_start: flow.start || null
    },

    http: {
      method: httpMethod,
      scheme: url && url.startsWith("https") ? "https" : "http",
      version: http.protocol || null,
      host: http.hostname || null,
      path: path,
      query: query,
      query_decoded: queryDecoded,
      status_code: httpStatus,
      content_type: http.http_content_type || null,
      user_agent: http.http_user_agent || null,
      referrer: http.http_refer || null,
      response_length: toInt(http.length),
      request_complete:
        data.ts_progress === null || data.ts_progress === undefined
          ? null
          : data.ts_progress === "request_complete",
      response_complete:
        data.tc_progress === null || data.tc_progress === undefined
          ? null
          : data.tc_progress === "response_complete"
    },

    derived: {
      retrieval_text: retrievalText,
      renderer_version: "n8n-wazuh-suricata-1.2",
      normalization: {
        selected_behavior: behavior.behavior,
        minimum_score: 2,
        behavior_scores: behavior.scores
      },
      external_hints: {
        wazuh_mitre: wazuhRule.mitre || null,
        wazuh_alert_tags: tags,
        wazuh_rule_groups: groups
      }
    },

    raw_reference: {
      source_system: "wazuh-opensearch",
      raw_event_id: src.id || null
    }
  };
}

const output = [];

for (const item of items) {
  const body = item.json.body || item.json;

  let sources = [];

  if (body.hits && Array.isArray(body.hits.hits)) {
    sources = body.hits.hits.map(hit => hit._source || hit);
  } else if (Array.isArray(body)) {
    sources = body;
  } else {
    sources = [body._source || body];
  }

  for (const src of sources) {
    const normalized = normalizeWazuhAlert(src);
    output.push({
      json: {
        normalized_alert: normalized
      }
    });
  }
}

return output;
