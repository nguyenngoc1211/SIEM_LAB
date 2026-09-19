function toInt(value) {
  if (value === null || value === undefined) return null;
  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? null : parsed;
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

function normalizeWazuhAlert(src) {
  const data = src.data || {};
  const alert = data.alert || {};
  const http = data.http || {};
  const flow = data.flow || {};
  const wazuhRule = src.rule || {};
  const metadata = alert.metadata || {};
  const tags = metadata.tag || [];
  const groups = wazuhRule.groups || [];

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

  const isWebAttack =
    alert.category === "Web Application Attack" ||
    tags.includes("SQL_Injection") ||
    tags.includes("XSS") ||
    tags.includes("Cross_Site_Scripting");

  const isPup =
    alert.category === "Potentially Unwanted Program" ||
    groups.includes("adware") ||
    groups.includes("pup");

  let dataSourceCategory = "network_traffic";
  let dataSubcategory = "network_ids";
  let eventType = "unknown";
  let eventAction = "unknown";
  let outcome = "unknown";

  if (isWebAttack) {
    dataSourceCategory = "application";
    dataSubcategory = "network_ids";
    eventType = "application_attack";
    eventAction = "inject_web_input";
    outcome = "unknown";
  } else if (isPup) {
    dataSourceCategory = "application";
    dataSubcategory = "adware_pup";
    eventType = "application_activity";
    eventAction = "application_checkin";
    outcome = toInt(http.status) === 200 ? "success" : "unknown";
  } else if (data.app_proto === "http") {
    dataSourceCategory = "application";
    dataSubcategory = "network_ids";
    eventType = "application_activity";
    eventAction = "http_activity";
    outcome = toInt(http.status) === 200 ? "success" : "unknown";
  } else {
    dataSourceCategory = "network_traffic";
    dataSubcategory = "network_ids";
    eventType = "network_activity";
    eventAction = "network_alert";
  }

  const disposition = alert.action || "unknown";

  const level = toInt(wazuhRule.level);
  let normalizedSeverity = null;

  if (level !== null) {
    if (level >= 13) normalizedSeverity = 4;
    else if (level >= 10) normalizedSeverity = 3;
    else if (level >= 7) normalizedSeverity = 2;
    else if (level >= 4) normalizedSeverity = 1;
    else normalizedSeverity = 0;
  }

  let targetType = "unknown";

  if (
    (metadata.attack_target || []).includes("Web_Server") ||
    http.hostname
  ) {
    targetType = "application";
  } else {
    targetType = "host";
  }

  const retrievalParts = [];

  const add = (label, value) => {
    if (
      value !== null &&
      value !== undefined &&
      String(value).trim() !== ""
    ) {
      retrievalParts.push(`${label} ${cleanText(value)}`);
    }
  };

  add("rule", alert.signature);
  add("data source", `${dataSourceCategory} ${dataSubcategory}`);
  add("event", eventType);
  add("action", eventAction);
  add("outcome", outcome);
  add("disposition", disposition);
  add("target", targetType);
  add("target hostname", http.hostname);
  add("target port", data.dest_port);
  add("target resource", path);
  add("http method", http.http_method);
  add("http path", path);
  add("http query", queryDecoded);
  add("http status", http.status);
  add("protocol", data.app_proto);
  add("direction", data.direction);
  add("tags", tags.join(" "));

  const retrievalText = retrievalParts
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();

  return {
    schema_version: "1.0",
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
      rule_name: alert.signature || wazuhRule.description || null
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
      source_value:
        alert.severity !== undefined && alert.severity !== null
          ? alert.severity
          : wazuhRule.level,
      source_scale: "suricata",
      normalized: normalizedSeverity
    },

    network: {
      transport_protocol: (data.proto || "").toLowerCase(),
      application_protocol: data.app_proto || null,
      direction: data.direction || null,
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
      method: http.http_method || null,
      scheme: url && url.startsWith("https") ? "https" : "http",
      version: http.protocol || null,
      host: http.hostname || null,
      path: path,
      query: query,
      query_decoded: queryDecoded,
      status_code: toInt(http.status),
      content_type: http.http_content_type || null,
      user_agent: http.http_user_agent || null,
      referrer: http.http_refer || null,
      response_length: toInt(http.length),
      request_complete: data.ts_progress === "request_complete",
      response_complete: data.tc_progress === "response_complete"
    },

    derived: {
      retrieval_text: retrievalText,
      renderer_version: "n8n-wazuh-suricata-1.0",
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