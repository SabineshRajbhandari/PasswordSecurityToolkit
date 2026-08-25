import React, { useState } from "react";
import "./PasswordGenerator.css";
import {
  DEFAULT_PASSWORD_OPTIONS,
  generatePassword as generateSecurePassword,
} from "./generator/passwordGenerator.js";
import {
  DEFAULT_PASSPHRASE_OPTIONS,
  generatePassphrase,
} from "./generator/passphraseGenerator.js";
import {
  MAX_PASSWORD_LENGTH,
  MAX_PASSPHRASE_WORDS,
  MIN_PASSWORD_LENGTH,
  MIN_PASSPHRASE_WORDS,
} from "./generator/characterSets.js";
import { analyzePassword } from "./analysis/passwordAnalyzer.js";
import { checkPasswordBreach } from "./breach/hibpClient.js";
import {
  DEFAULT_POLICY,
  POLICY_PRESETS,
  evaluatePasswordPolicy,
  validatePolicy,
} from "./policy/policyEngine.js";
import {
  createSecurityReport,
  serializeReport,
} from "./report/securityReport.js";

export default function PasswordGenerator() {
  const [mode, setMode] = useState("password");
  const [passwordOptions, setPasswordOptions] = useState(DEFAULT_PASSWORD_OPTIONS);
  const [passphraseOptions, setPassphraseOptions] = useState(DEFAULT_PASSPHRASE_OPTIONS);
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const [analysisInput, setAnalysisInput] = useState("");
  const [showAnalysisPassword, setShowAnalysisPassword] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [breachResult, setBreachResult] = useState({ status: "idle" });
  const [policy, setPolicy] = useState(DEFAULT_POLICY);
  const [policyResult, setPolicyResult] = useState(null);
  const [securityReport, setSecurityReport] = useState(null);
  const [activeMetricHelp, setActiveMetricHelp] = useState(null);

  const updatePasswordOption = (option, value) => {
    setPasswordOptions((current) => ({ ...current, [option]: value }));
  };

  const updatePassphraseOption = (option, value) => {
    setPassphraseOptions((current) => ({ ...current, [option]: value }));
  };

  const switchMode = (nextMode) => {
    setMode(nextMode);
    setGeneratedPassword("");
    setCopied(false);
    setError("");
  };

  const generate = () => {
    try {
      const generated = mode === "password"
        ? generateSecurePassword(passwordOptions)
        : generatePassphrase(passphraseOptions);
      setGeneratedPassword(generated);
      setError("");
    } catch (generationError) {
      setError(generationError.message);
    }
    setCopied(false);
  };

  const copyToClipboard = async (value) => {
    if (value) {
      try {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setError("");
      } catch {
        setError("Clipboard access was unavailable. Copy the value manually.");
      }
      setTimeout(() => setCopied(false), 1500);
    }
  };

  const analyze = () => {
    setAnalysisResult(analyzePassword(analysisInput));
    try {
      const validated = validatePolicy(policy);
      setPolicyResult(evaluatePasswordPolicy(analysisInput, validated, breachResult));
    } catch (policyError) {
      setPolicyResult({
        compliant: false,
        passedRules: [],
        failedRules: [policyError.message],
        warnings: ["Policy configuration is invalid."],
        recommendations: ["Review the minimum and maximum length settings and character requirements."],
        breachStatus: breachResult.status === "found" || breachResult.status === "not_found" || breachResult.status === "error" ? breachResult.status : "not_checked",
      });
    }
  };

  const checkBreach = async () => {
    setBreachResult({ status: "checking" });
    try {
      const result = await checkPasswordBreach(analysisInput);
      setBreachResult(result);
    } catch (breachError) {
      const message = breachError.message.includes("temporarily unavailable")
        ? breachError.message
        : breachError.message.includes("cryptographic hashing is unavailable")
          ? "Local cryptographic hashing is unavailable in this browser."
          : "Unable to contact the breach-check service. Your password was not classified as safe; the check could not be completed.";
      setBreachResult({ status: "error", message });
    }
  };

  const clearAnalysis = () => {
    setAnalysisInput("");
    setShowAnalysisPassword(false);
    setAnalysisResult(null);
    setBreachResult({ status: "idle" });
    setPolicyResult(null);
    setSecurityReport(null);
  };

  const activePassword = generatedPassword;

  const updatePolicySetting = (field, value) => {
    setPolicy((current) => ({ ...current, [field]: value }));
  };

  const applyPreset = (presetName) => {
    const preset = POLICY_PRESETS[presetName];
    if (preset) {
      setPolicy({ ...preset });
    }
  };

  const evaluatePolicySettings = () => {
    try {
      const validated = validatePolicy(policy);
      const nextPolicyResult = evaluatePasswordPolicy(analysisInput, validated, breachResult);
      setPolicyResult(nextPolicyResult);

      if (analysisInput && analysisResult) {
        setSecurityReport(createSecurityReport({
          analysis: analysisResult,
          breach: breachResult,
          policy: nextPolicyResult,
          policyPreset: "CUSTOM",
        }));
      }
    } catch (policyError) {
      const nextPolicyResult = {
        compliant: false,
        passedRules: [],
        failedRules: [policyError.message],
        warnings: ["Policy configuration is invalid."],
        recommendations: ["Review the minimum and maximum length settings and character requirements."],
        breachStatus: breachResult.status === "found" || breachResult.status === "not_found" || breachResult.status === "error" ? breachResult.status : "not_checked",
      };
      setPolicyResult(nextPolicyResult);
      if (analysisInput && analysisResult) {
        setSecurityReport(createSecurityReport({
          analysis: analysisResult,
          breach: breachResult,
          policy: nextPolicyResult,
          policyPreset: "CUSTOM",
        }));
      }
    }
  };

  const tips = [
    { text: "Use at least 12 characters", pass: activePassword.length >= 12 },
    { text: "Include uppercase letters", pass: /[A-Z]/.test(activePassword) },
    { text: "Include numbers", pass: /[0-9]/.test(activePassword) },
    { text: "Include symbols (!@#$%^&*())", pass: /[!@#$%^&*()]/.test(activePassword) },
  ];

  return (
    <div className="container" role="main">
      <header className="toolkit-header">
        <div>
          <p className="brand-kicker">Security console / local assessment</p>
          <h1 tabIndex={0}>Password Security Toolkit</h1>
          <p className="header-description">Privacy-first password generation, analysis, policy evaluation, and breach intelligence in your browser.</p>
        </div>
      </header>

      <section className="generator-panel" aria-labelledby="generator-heading">
        <div className="panel-title-row">
          <div>
            <p className="section-kicker">Generate a new secret</p>
            <h2 id="generator-heading">Password Generator</h2>
          </div>
          <span className="mode-label">{mode === "password" ? "Character-based" : "Word-based"}</span>
        </div>

        <div className="mode-switch" role="group" aria-label="Generation mode">
          <button
            className={mode === "password" ? "mode-button active" : "mode-button"}
            onClick={() => switchMode("password")}
            type="button"
          >
            Password
          </button>
          <button
            className={mode === "passphrase" ? "mode-button active" : "mode-button"}
            onClick={() => switchMode("passphrase")}
            type="button"
          >
            Passphrase
          </button>
        </div>

        <div className="password-box" aria-live="polite" aria-label="Generated value">
          <div className="generated-display">
            <span className="generated-label">Generated {mode === "password" ? "password" : "passphrase"}</span>
            {generatedPassword ? (
              <span className="password-text">{generatedPassword}</span>
            ) : (
              <button className="generate-placeholder" onClick={generate} type="button">
                Generate {mode === "password" ? "Password" : "Passphrase"}
              </button>
            )}
          </div>
        </div>

        {generatedPassword && (
          <div className="generated-actions" aria-label="Generated password actions">
            <button className="regenerate-button" onClick={generate} aria-label={`Generate another ${mode}`} type="button">
              Regenerate
            </button>
            <button className={`copy-button ${copied ? "is-copied" : ""}`} onClick={() => copyToClipboard(generatedPassword)} aria-label={copied ? "Copied generated value" : "Copy generated value"} type="button">
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        )}

        {mode === "password" ? (
        <>
          <fieldset className="options-panel">
            <legend>
              <span>Password options</span>
              <small>Customize the character types and length.</small>
            </legend>
            <p className="panel-description">Choose the character groups the generator may use. More groups create a larger selection pool.</p>
            <label htmlFor="length-slider">Length: {passwordOptions.length}</label>
            <input
              id="length-slider"
              type="range"
              min={MIN_PASSWORD_LENGTH}
              max={MAX_PASSWORD_LENGTH}
              value={passwordOptions.length}
              onChange={(event) => updatePasswordOption("length", Number(event.target.value))}
              aria-label="Password length slider"
            />
            <div className="checkbox-grid">
              {["lowercase", "uppercase", "digits", "symbols"].map((option) => (
                <label key={option}>
                  <input type="checkbox" checked={passwordOptions[option]} onChange={(event) => updatePasswordOption(option, event.target.checked)} />
                  {option[0].toUpperCase() + option.slice(1)}
                </label>
              ))}
              <label>
                <input type="checkbox" checked={passwordOptions.excludeAmbiguous} onChange={(event) => updatePasswordOption("excludeAmbiguous", event.target.checked)} />
                Exclude ambiguous
              </label>
            </div>
          </fieldset>
        </>
      ) : (
        <fieldset className="options-panel">
          <legend>
            <span>Passphrase options</span>
            <small>Choose words, separators, and optional extras.</small>
          </legend>
          <p className="panel-description">Choose how many random words to combine. More words generally make a passphrase longer and harder to guess.</p>
          <label htmlFor="word-count">Words: {passphraseOptions.wordCount}</label>
          <input
            id="word-count"
            type="range"
            min={MIN_PASSPHRASE_WORDS}
            max={MAX_PASSPHRASE_WORDS}
            value={passphraseOptions.wordCount}
            onChange={(event) => updatePassphraseOption("wordCount", Number(event.target.value))}
            aria-label="Passphrase word count"
          />
          <label htmlFor="separator">Separator</label>
          <input id="separator" value={passphraseOptions.separator} maxLength={8} onChange={(event) => updatePassphraseOption("separator", event.target.value)} />
          <div className="checkbox-grid">
            <label><input type="checkbox" checked={passphraseOptions.capitalize} onChange={(event) => updatePassphraseOption("capitalize", event.target.checked)} /> Capitalize</label>
            <label><input type="checkbox" checked={passphraseOptions.includeNumbers} onChange={(event) => updatePassphraseOption("includeNumbers", event.target.checked)} /> Add number</label>
            <label><input type="checkbox" checked={passphraseOptions.includeSymbols} onChange={(event) => updatePassphraseOption("includeSymbols", event.target.checked)} /> Add symbol</label>
          </div>
        </fieldset>
        )}

        {error && <div className="error-message" role="alert">{error}</div>}

        <div className="suggestions" aria-live="polite" aria-label="Password tips">
          <h3>Password Tips:</h3>
          <ul>
            {tips.map((tip) => <li key={tip.text} className={`tip ${tip.pass ? "pass" : "fail"}`}>{tip.text}</li>)}
          </ul>
        </div>

        <section className="mode-explanation" aria-labelledby="mode-explanation-heading">
          <div>
            <p className="eyebrow">About this mode</p>
            <h2 id="mode-explanation-heading">
              {mode === "password" ? "Random passwords for strict requirements" : "Memorable passphrases for everyday use"}
            </h2>
            <p>
              {mode === "password"
                ? "A password is a compact string of randomly selected characters. Use this mode when a website requires specific character types or a shorter fixed format."
                : "A passphrase is a sequence of randomly selected words joined by a separator. It is easier to read, type, and remember while still gaining strength from multiple random words."}
            </p>
            <p className="how-it-works">
              <strong>How it works:</strong>{" "}
              {mode === "password"
                ? "The generator uses your selected character sets and a browser cryptographic random source to build a fresh value."
                : "The generator securely chooses words from its local word list, joins them with your separator, and can add a random number or symbol."}
            </p>
          </div>
          <div className="why-choose">
            <strong>{mode === "passphrase" ? "Where is a passphrase useful?" : "Where is a password useful?"}</strong>
            <span>
              {mode === "password"
                ? "Best for websites, devices, and systems with strict password rules."
                : "Useful for password-manager entries, recovery codes, Wi-Fi settings, and systems where typing or remembering the value matters."}
            </span>
          </div>
        </section>
      </section>

      <section className="analysis-panel" aria-labelledby="analysis-heading">
        <h2 id="analysis-heading">Password Security Analysis</h2>
        <p className="analysis-note">Analysis runs locally and the password is not sent or stored.</p>
        <div className="analysis-input-wrap">
          <input
            type={showAnalysisPassword ? "text" : "password"}
            className="analysis-input"
            value={analysisInput}
            onChange={(event) => {
              setAnalysisInput(event.target.value);
              setAnalysisResult(null);
              setBreachResult({ status: "idle" });
              setPolicyResult(null);
              setSecurityReport(null);
            }}
            placeholder="Enter a password to analyze"
            aria-label="Password to analyze"
            autoComplete="off"
          />
          <button
            className="password-visibility-button"
            type="button"
            onClick={() => setShowAnalysisPassword((visible) => !visible)}
            aria-label={showAnalysisPassword ? "Hide password" : "Show password"}
            aria-pressed={showAnalysisPassword}
            title={showAnalysisPassword ? "Hide password" : "Show password"}
          >
            <span aria-hidden="true">{showAnalysisPassword ? "Hide" : "Show"}</span>
          </button>
        </div>
        <div className="analysis-actions">
          <button className="generate-button analysis-button" onClick={analyze} disabled={!analysisInput} type="button">Analyze Password</button>
          <button className="clear-button" onClick={clearAnalysis} disabled={!analysisInput && !analysisResult} type="button">Clear</button>
        </div>

        <SecurityOverview
          analysis={analysisResult}
          breach={breachResult}
          policy={policyResult}
          activeMetricHelp={activeMetricHelp}
          setActiveMetricHelp={setActiveMetricHelp}
        />

        <div className="breach-check" aria-labelledby="breach-heading">
          <div className="section-heading">
            <div>
              <p className="section-kicker">External intelligence</p>
              <h3 id="breach-heading">Breach Exposure</h3>
            </div>
            <StatusBadge status={breachResult.status === "idle" ? "not_checked" : breachResult.status} label={breachResult.status === "idle" ? "Not checked" : breachResult.status} />
          </div>
          <p className="privacy-notice">Privacy: your password is hashed locally. Only the first 5 characters of its SHA-1 hash are sent to HIBP. The password and full hash remain local. This reduces direct exposure but does not make the network request anonymous.</p>
          <button className="clear-button" onClick={checkBreach} disabled={!analysisInput || breachResult.status === "checking"} type="button">
            {breachResult.status === "checking" ? "Checking..." : "Check Breach Exposure"}
          </button>
          <BreachResult result={breachResult} />
        </div>

        <div className="policy-panel" aria-labelledby="policy-heading">
          <div className="section-heading">
            <div>
              <p className="section-kicker">Rules and requirements</p>
              <h3 id="policy-heading">Password Policy</h3>
            </div>
            <StatusBadge status={policyResult ? (policyResult.compliant ? "pass" : "failed") : "not_checked"} label={policyResult ? (policyResult.compliant ? "Pass" : "Failed") : "Not checked"} />
          </div>
          <div className="preset-row">
            {Object.keys(POLICY_PRESETS).map((presetName) => (
              <button key={presetName} className="clear-button preset-button" onClick={() => applyPreset(presetName)} type="button">
                {presetName}
              </button>
            ))}
          </div>
          <div className="policy-grid">
            <label>
              Minimum length
              <input type="number" min="0" max="256" value={policy.minimumLength} onChange={(event) => updatePolicySetting("minimumLength", Number(event.target.value))} />
            </label>
            <label>
              Maximum length
              <input type="number" min="0" max="256" value={policy.maximumLength} onChange={(event) => updatePolicySetting("maximumLength", Number(event.target.value))} />
            </label>
          </div>
          <p className="control-group-label">Character requirements and security restrictions</p>
          <div className="checkbox-grid policy-checks">
            {[
              ["requireLowercase", "Lowercase required"],
              ["requireUppercase", "Uppercase required"],
              ["requireDigit", "Digit required"],
              ["requireSymbol", "Symbol required"],
              ["rejectCommonPasswords", "Common password rejected"],
              ["rejectRepeatedCharacters", "Repeated characters rejected"],
              ["rejectSequentialCharacters", "Sequential characters rejected"],
              ["rejectPredictablePatterns", "Predictable patterns rejected"],
              ["rejectBreachedPasswords", "Breach requirement"],
            ].map(([field, label]) => (
              <label key={field}>
                <input type="checkbox" checked={policy[field]} onChange={(event) => updatePolicySetting(field, event.target.checked)} />
                {label}
              </label>
            ))}
          </div>
          <button className="generate-button analysis-button" onClick={evaluatePolicySettings} type="button">Evaluate Policy</button>
          {policyResult && (
            <div className="policy-result" aria-live="polite">
              <p className={`policy-status ${policyResult.compliant ? "status-pass" : "status-failed"}`}><strong>{policyResult.compliant ? "PASS · Policy compliant" : "FAILED · Policy requirements not met"}</strong></p>
              <p className="result-counts"><strong>{policyResult.passedRules.length}</strong> rules passed <span aria-hidden="true">·</span> <strong>{policyResult.failedRules.length}</strong> rules failed</p>
              <p><strong>Breach status:</strong> {policyResult.breachStatus}</p>
              <PolicyList title="Passed rules" items={policyResult.passedRules} />
              <PolicyList title="Failed rules" items={policyResult.failedRules} />
              <PolicyList title="Warnings" items={policyResult.warnings} />
              <PolicyList title="Recommendations" items={policyResult.recommendations} />
            </div>
          )}
        </div>

        {analysisResult && <AnalysisResult result={analysisResult} />}

        {securityReport && (
          <div className="security-report" aria-labelledby="security-report-heading">
            <div className="section-heading">
              <div>
                <p className="section-kicker">Sanitized assessment</p>
                <h3 id="security-report-heading">Security Assessment</h3>
              </div>
              <StatusBadge status={securityReport.overallAssessment.level.toLowerCase()} label={securityReport.overallAssessment.level} />
            </div>
            <div className="report-summary">
              <strong>{securityReport.findings.length} security finding{securityReport.findings.length === 1 ? "" : "s"} detected</strong>
              <span>{securityReport.overallAssessment.summary}</span>
            </div>
            <p><strong>Summary:</strong> {securityReport.summary}</p>
            <p><strong>Breach status:</strong> {securityReport.breachStatus}</p>
            <p><strong>Policy status:</strong> {securityReport.policyStatus}</p>

            <h4>Findings</h4>
            <ul>
              {securityReport.findings.map((finding) => (
                <li key={`${finding.category}-${finding.title}`}>
                  <strong>{finding.severity.toUpperCase()}:</strong> {finding.title} — {finding.explanation}
                </li>
              ))}
            </ul>

            <h4>Recommendations</h4>
            <ul>
              {securityReport.recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}
            </ul>

            <button
              className="clear-button"
              type="button"
              onClick={() => navigator.clipboard?.writeText(serializeReport(securityReport))}
            >
              Copy JSON Report
            </button>
          </div>
        )}

      </section>
    </div>
  );
}

function SecurityOverview({ analysis, breach, policy, activeMetricHelp, setActiveMetricHelp }) {
  const predictability = analysis
    ? analysis.patterns.length === 0 ? "Low" : analysis.patterns.some((pattern) => pattern.risk === "high") ? "High" : "Review"
    : "Not checked";
  const breachStatus = breach.status === "idle" ? "Not checked" : breach.status === "not_found" ? "No match" : breach.status;
  const cards = [
    { label: "Strength", help: "A local score based on length, character variety, repetition, entropy, and detected patterns.", value: analysis?.strength || "Not checked", detail: analysis ? `${analysis.score}/100 local score` : "Run local analysis", status: analysis ? analysis.strength : "not_checked" },
    { label: "Entropy", help: "A theoretical estimate of the password's search space. It is not a crack-time guarantee.", value: analysis ? `${analysis.entropy.bits} bits` : "Not checked", detail: "Theoretical estimate", status: analysis ? "informational" : "not_checked" },
    { label: "Predictability", help: "Indicates whether local pattern checks found repeated, sequential, or recognizable patterns.", value: predictability, detail: analysis ? `${analysis.patterns.length} pattern${analysis.patterns.length === 1 ? "" : "s"} detected` : "Run local analysis", status: analysis ? predictability.toLowerCase() : "not_checked" },
    { label: "Policy", help: "Shows whether the password meets the currently selected length, character, and restriction rules.", value: policy ? policy.compliant ? "Pass" : "Failed" : "Not checked", detail: policy ? `${policy.failedRules.length} failed rule${policy.failedRules.length === 1 ? "" : "s"}` : "Evaluate policy", status: policy ? policy.compliant ? "pass" : "failed" : "not_checked" },
    { label: "Breach", help: "The explicit HIBP lookup state. Not checked or no match does not prove the password is safe.", value: breachStatus.replace("_", " "), detail: breach.status === "found" ? "Known exposure detected" : "Explicit HIBP status", status: breach.status === "idle" ? "not_checked" : breach.status },
  ];

  return (
    <section className="security-overview" aria-labelledby="overview-heading">
      <div className="section-heading overview-heading">
        <div>
          <p className="section-kicker">At a glance</p>
          <h3 id="overview-heading">Security Overview</h3>
        </div>
        <span className="overview-note">No aggregate security score</span>
      </div>
      <div className="overview-grid">
        {cards.map((card) => (
          <div className="overview-card" key={card.label}>
            <div className="overview-card-heading">
              <span className="overview-card-label">{card.label}</span>
              <button
                className={`metric-help ${activeMetricHelp === card.label ? "is-open" : ""}`}
                type="button"
                aria-label={`About ${card.label}`}
                aria-expanded={activeMetricHelp === card.label}
                onClick={() => setActiveMetricHelp((current) => current === card.label ? null : card.label)}
              >
                <span aria-hidden="true">i</span>
                <span className="metric-tooltip" role="tooltip">{card.help}</span>
              </button>
            </div>
            <StatusBadge status={card.status} label={card.value} />
            <span className="overview-card-detail">{card.detail}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function StatusBadge({ status, label }) {
  const normalizedStatus = status.replaceAll(" ", "-").toLowerCase();
  const symbol = ["pass", "good", "strong", "very-strong", "low", "not_found", "not-found"].includes(normalizedStatus)
    ? "✓"
    : ["failed", "critical", "high", "weak", "found"].includes(normalizedStatus)
      ? "!"
      : normalizedStatus === "checking"
        ? "..."
        : "?";

  return <span className={`status-badge status-${normalizedStatus}`}><span aria-hidden="true">{symbol}</span>{label}</span>;
}

function BreachResult({ result }) {
  if (result.status === "idle") return <p className="breach-status">No breach check requested.</p>;
  if (result.status === "checking") return <p className="breach-status">Checking the HIBP Pwned Passwords dataset...</p>;
  if (result.status === "found") return <p className="breach-status breach-found">Found in known breaches. Reported occurrences: {result.count.toLocaleString()}.</p>;
  if (result.status === "not_found") return <p className="breach-status breach-clear">Not found in the HIBP Pwned Passwords dataset. This does not prove the password is safe.</p>;
  return <p className="breach-status breach-error" role="alert">{result.message}</p>;
}

function AnalysisResult({ result }) {
  const categories = [
    ["Lowercase", result.characterSets.lowercase],
    ["Uppercase", result.characterSets.uppercase],
    ["Digits", result.characterSets.digits],
    ["Symbols", result.characterSets.symbols],
  ];

  return (
    <div className="analysis-result" aria-live="polite">
      <div className="analysis-summary">
        <strong>{result.strength}</strong>
        <span>Score: {result.score}/100</span>
        <span>Theoretical entropy: {result.entropy.bits} bits</span>
      </div>
      <p>{result.entropy.assumptions[1]}</p>
      <div className="analysis-characteristics">
        <span>Length: {result.length.value} ({result.length.rating})</span>
        <span>Character sets: {result.characterSets.characterSetCount}/4</span>
        <span>Unique characters: {result.characterSets.uniqueCharacters}</span>
        {categories.map(([label, present]) => <span key={label}>{label}: {present ? "Yes" : "No"}</span>)}
        <span>Common password: {result.commonPassword.detected ? "Detected" : "Not detected"}</span>
      </div>
      <AnalysisList title="Warnings" items={result.warnings} emptyText="No immediate warnings detected." />
      <AnalysisList title="Recommendations" items={result.recommendations} />
      {result.patterns.length > 0 && (
        <div>
          <h3>Detected patterns</h3>
          <ul>
            {result.patterns.map((finding) => (
              <li key={finding.type}>
                <strong>{finding.type}:</strong> {finding.explanation} {finding.recommendation}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function AnalysisList({ title, items, emptyText }) {
  return (
    <div>
      <h3>{title}</h3>
      {items.length > 0 ? <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul> : <p>{emptyText}</p>}
    </div>
  );
}

function PolicyList({ title, items }) {
  if (!items || items.length === 0) {
    return null;
  }

  return (
    <div>
      <h4>{title}</h4>
      <ul>
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </div>
  );
}
