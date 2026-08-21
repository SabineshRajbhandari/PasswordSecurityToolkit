const SECRET_KEY_PATTERNS = [
  "password",
  "plaintext",
  "fullhash",
  "fullHash",
  "sha1hash",
  "sha1Hash",
  "sha1",
  "hibp",
  "hashprefix",
  "hashprefix",
  "hashsuffix",
  "hashSuffix",
  "hash",
  "prefix",
  "suffix",
  "passphrase",
];

function normalizeStatus(status) {
  if (!status || status === "idle") return "not_checked";
  if (status === "found") return "found";
  if (status === "not_found") return "not_found";
  if (status === "error" || status === "unavailable") return "unavailable";
  return "not_checked";
}

function dedupe(items = []) {
  return [...new Set(items.filter(Boolean))];
}

function sanitizeForReport(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeForReport(item));
  }

  if (value && typeof value === "object") {
    const cleaned = {};
    for (const [key, item] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase();
      if (SECRET_KEY_PATTERNS.some((pattern) => normalizedKey.includes(pattern))) {
        continue;
      }
      cleaned[key] = sanitizeForReport(item);
    }
    return cleaned;
  }

  return value;
}

function assessmentForScore(score, breachStatus, policyCompliant, hasCommonPassword, hasPatterns) {
  if (breachStatus === "found") return {
    level: "Critical",
    summary: "Strong local characteristics, but breach exposure was detected.",
  };

  if (breachStatus === "unavailable") return {
    level: "Medium",
    summary: "breach status is unavailable, so the report remains uncertain and the password should not be treated as absolutely safe.",
  };

  if (!policyCompliant || hasCommonPassword || hasPatterns || score < 40) {
    return {
      level: "High",
      summary: "Local characteristics are mixed and the password does not meet the preferred security posture.",
    };
  }

  if (score >= 80) {
    return {
      level: "Good",
      summary: "Local analysis indicates strong characteristics and the password aligns with the configured policy.",
    };
  }

  if (score >= 60) {
    return {
      level: "Low",
      summary: "The password has acceptable local characteristics, but a few improvements would strengthen it.",
    };
  }

  return {
    level: "Medium",
    summary: "Local characteristics are acceptable but not especially strong; a more robust password would be better.",
  };
}

function createFinding({ severity, category, title, explanation, recommendation }) {
  return {
    severity,
    category,
    title,
    explanation,
    recommendation,
  };
}

function deriveFindings(analysis, breach, policy) {
  const findings = [];

  if (analysis?.commonPassword?.detected) {
    findings.push(createFinding({
      severity: "high",
      category: "local-analysis",
      title: "Common password detected",
      explanation: "The password matches a locally known common password list.",
      recommendation: "Choose a unique password that is not commonly reused or guessed.",
    }));
  }

  if (Array.isArray(analysis?.patterns) && analysis.patterns.length > 0) {
    for (const pattern of analysis.patterns) {
      const risk = pattern.risk || "medium";
      findings.push(createFinding({
        severity: risk === "high" ? "high" : "medium",
        category: "local-analysis",
        title: pattern.type || "Predictable pattern",
        explanation: pattern.explanation || "The password includes a pattern that reduces guessing resistance.",
        recommendation: pattern.recommendation || "Remove the reported pattern and use a less predictable password.",
      }));
    }
  }

  if (analysis?.score !== undefined && analysis.score < 40) {
    findings.push(createFinding({
      severity: "high",
      category: "local-analysis",
      title: "Weak local strength",
      explanation: "The password has a low local strength score and limited practical resistance against guessing.",
      recommendation: "Use a longer, less predictable password or a randomly generated value.",
    }));
  }

  if (breach?.status === "found") {
    findings.push(createFinding({
      severity: "critical",
      category: "breach",
      title: "Breach exposure detected",
      explanation: "The password appears in known breach data and should be treated as exposed.",
      recommendation: "Replace the password immediately and rotate it across any affected services.",
    }));
  } else if (breach?.status === "error" || breach?.status === "unavailable") {
    findings.push(createFinding({
      severity: "medium",
      category: "breach",
      title: "Breach check unavailable",
      explanation: "The breach check could not finish, so the breach status remains uncertain.",
      recommendation: "Retry the breach check later or prefer a stronger, more unique password while the status is uncertain.",
    }));
  }

  if (policy && !policy.compliant) {
    for (const failure of policy.failedRules || []) {
      findings.push(createFinding({
        severity: "medium",
        category: "policy",
        title: "Policy requirement not met",
        explanation: failure,
        recommendation: "Adjust the password to meet the configured policy requirements.",
      }));
    }
  }

  return dedupe(findings.map((finding) => JSON.stringify(finding))).map((entry) => JSON.parse(entry));
}

function deriveRecommendations(analysis, breach, policy) {
  const recommendations = [];

  if (analysis?.recommendations?.length) recommendations.push(...analysis.recommendations);
  if (policy?.recommendations?.length) recommendations.push(...policy.recommendations);
  if (breach?.status === "found") recommendations.push("Replace a password found in known breaches.");
  if (analysis?.score !== undefined && analysis.score < 60) recommendations.push("Increase password length.");
  if (analysis?.commonPassword?.detected) recommendations.push("Avoid common passwords.");
  if (analysis?.patterns?.length) recommendations.push("Avoid predictable patterns.");

  return dedupe(recommendations);
}

export function serializeReport(report) {
  return JSON.stringify(sanitizeForReport(report), null, 2);
}

export function createSecurityReport({
  analysis = {},
  breach = {},
  policy = null,
  policyPreset = "DEFAULT",
  generatedAt = new Date().toISOString(),
} = {}) {
  const normalizedAnalysis = sanitizeForReport(analysis);
  const normalizedBreach = sanitizeForReport(breach);
  const normalizedPolicy = sanitizeForReport(policy || { compliant: true, failedRules: [], recommendations: [], warnings: [], breachStatus: normalizeStatus(breach?.status) });

  const policyStatus = normalizedPolicy.breachStatus || normalizeStatus(normalizedBreach.status);
  const findings = deriveFindings(normalizedAnalysis, normalizedBreach, normalizedPolicy);
  const recommendations = deriveRecommendations(normalizedAnalysis, normalizedBreach, normalizedPolicy);

  const overallAssessment = assessmentForScore(
    Number(normalizedAnalysis.score ?? 0),
    normalizeStatus(normalizedBreach.status),
    normalizedPolicy.compliant !== false,
    Boolean(normalizedAnalysis.commonPassword?.detected),
    Array.isArray(normalizedAnalysis.patterns) && normalizedAnalysis.patterns.length > 0,
  );

  const report = {
    generatedAt,
    metadata: {
      toolkitVersion: "Password Security Toolkit",
      analyzerVersion: "phase-5-reporting",
      policyPreset,
      breachStatus: normalizeStatus(normalizedBreach.status),
      reportType: "security-report",
    },
    analysis: {
      strength: normalizedAnalysis.strength || "Unknown",
      score: normalizedAnalysis.score ?? 0,
      entropy: normalizedAnalysis.entropy || { bits: 0 },
      warnings: Array.isArray(normalizedAnalysis.warnings) ? normalizedAnalysis.warnings : [],
      recommendations: Array.isArray(normalizedAnalysis.recommendations) ? normalizedAnalysis.recommendations : [],
      patterns: Array.isArray(normalizedAnalysis.patterns) ? normalizedAnalysis.patterns : [],
      commonPassword: normalizedAnalysis.commonPassword || { detected: false },
    },
    breach: normalizedBreach,
    policy: normalizedPolicy,
    policyStatus,
    breachStatus: normalizeStatus(normalizedBreach.status),
    overallAssessment: {
      level: overallAssessment.level,
      summary: overallAssessment.summary,
    },
    findings,
    recommendations,
    summary: overallAssessment.summary,
  };

  return sanitizeForReport(report);
}
