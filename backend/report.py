from datetime import datetime
from zoneinfo import ZoneInfo

IST_TZ = ZoneInfo("Asia/Kolkata")

def get_risk_percentage(score):
    # Scale score (heuristic max usually around 10-15) to 0-100
    return min(100, int((score / 10.0) * 100))

def build_report_html(url, score, verdict, triggered_rules, google_safe_browsing=None):
    scan_time = datetime.now(IST_TZ).strftime("%d/%m/%Y, %I:%M:%S %p IST")
    risk_pct = get_risk_percentage(score)

    badge_color = "#10b981" if verdict == "Safe" else ("#f59e0b" if verdict == "Suspicious" else "#ef4444")
    badge_bg = "rgba(16, 185, 129, 0.15)" if verdict == "Safe" else ("rgba(245, 158, 11, 0.15)" if verdict == "Suspicious" else "rgba(239, 68, 68, 0.15)")

    recommendations = []
    explanations = []
    if verdict == "Phishing":
        recommendations = [
            "DO NOT click any links or enter credentials, OTPs, or financial details.",
            "Block this domain and IP address at the firewall/DNS proxy level.",
            "Report this URL to Google Safe Browsing and your organisation's SOC.",
            "If already accessed, immediately invalidate session tokens and rotate passwords."
        ]
        explanations = [
            "Multiple severe phishing heuristics triggered (e.g. brand spoofing, malicious keyword masking, or deceptive redirect).",
            "This URL structure closely matches active credential harvesting and social engineering campaigns."
        ]
    elif verdict == "Suspicious":
        recommendations = [
            "Exercise extreme caution; do not submit sensitive or personal credentials.",
            "Verify the true sender domain via whois and SSL certificate transparency logs.",
            "Inspect in an isolated browser sandbox before interacting.",
            "Look for deceptive homograph characters or subdomains simulating known services."
        ]
        explanations = [
            "Several anomalous indicators detected (e.g. uncommon TLD, excessive subdomains, or URL shortener).",
            "While not definitively flagged as an active attack, the risk profile is significantly elevated."
        ]
    else:
        recommendations = [
            "No immediate heuristic anomalies or known phishing markers were found.",
            "Standard security hygiene: always verify HTTPS certificate validity before logging in.",
            "Continue periodic security monitoring."
        ]
        explanations = [
            "Standard URL structure with no obvious impersonation patterns detected by the rule engine."
        ]

    rules_html = ""
    if triggered_rules:
        for r in triggered_rules:
            rules_html += f"""
            <div style="background: rgba(255,255,255,0.04); border-left: 3px solid #06b6d4; padding: 10px 14px; margin-bottom: 8px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 600; color: #e2e8f0;">{r.get('name', 'Rule')}</span>
                    <span style="background: rgba(6, 182, 212, 0.2); color: #22d3ee; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold;">Weight +{r.get('weight', 1)}</span>
                </div>
                <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Rule ID: <code>{r.get('id', 'rule')}</code></div>
            </div>
            """
    else:
        rules_html = "<div style='color: #10b981; font-weight: 500; padding: 8px 0;'>✓ No heuristic risk triggers detected.</div>"

    gsb_html = ""
    if google_safe_browsing:
        matches = google_safe_browsing.get("matches", [])
        if matches:
            gsb_html = f"""
            <div style="background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 12px; margin-top: 14px;">
                <strong style="color: #ef4444;">External Threat Intel Alert:</strong>
                <p style="margin: 4px 0 0; font-size: 13px; color: #fca5a5;">Flagged by Google Safe Browsing as malicious threat match.</p>
            </div>
            """
        else:
            gsb_html = """
            <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px; padding: 10px 12px; margin-top: 14px;">
                <span style="color: #10b981; font-size: 13px;">✓ Google Safe Browsing: No active blacklisting found.</span>
            </div>
            """

    return f"""
    <div class="phishguard-report" style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #e2e8f0; background: #0b1120; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 28px; max-width: 850px; margin: 0 auto; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);">
      <!-- Header -->
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px; margin-bottom: 20px;">
        <div>
          <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #06b6d4; font-weight: 700;">Cyber Intelligence Command Center</div>
          <h1 style="font-size: 22px; font-weight: 700; margin: 4px 0; color: #f8fafc;">PhishGuard Security Risk Report</h1>
        </div>
        <div style="text-align: right;">
          <span style="display: inline-block; padding: 6px 14px; border-radius: 9999px; font-size: 14px; font-weight: 700; color: {badge_color}; background: {badge_bg}; border: 1px solid {badge_color};">
            {verdict.upper()}
          </span>
        </div>
      </div>

      <!-- Quick Metrics Grid -->
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 22px;">
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 14px;">
          <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Risk Score</div>
          <div style="font-size: 24px; font-weight: 800; color: {badge_color}; margin-top: 4px;">{score} <span style="font-size: 13px; font-weight: normal; color: #64748b;">({risk_pct}/100)</span></div>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 14px;">
          <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Rules Triggered</div>
          <div style="font-size: 24px; font-weight: 800; color: #38bdf8; margin-top: 4px;">{len(triggered_rules)}</div>
        </div>
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 14px;">
          <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Analysis Engine</div>
          <div style="font-size: 14px; font-weight: 600; color: #cbd5e1; margin-top: 8px;">Heuristic v2 + Intel</div>
        </div>
      </div>

      <!-- Analyzed URL -->
      <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 14px; margin-bottom: 22px;">
        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px;">Analyzed Target URL</div>
        <div style="word-break: break-all; font-family: monospace; font-size: 14px; color: #38bdf8;">{url}</div>
        <div style="font-size: 11px; color: #64748b; margin-top: 6px;">Scanned at: {scan_time}</div>
      </div>

      <!-- Risk Explanation -->
      <div style="margin-bottom: 22px;">
        <h3 style="font-size: 15px; color: #f1f5f9; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
          <span style="color: #06b6d4;">◆</span> Risk Assessment & Explanation
        </h3>
        <ul style="margin: 0; padding-left: 20px; color: #cbd5e1; font-size: 13.5px; line-height: 1.6;">
          {''.join(f"<li style='margin-bottom: 4px;'>{exp}</li>" for exp in explanations)}
        </ul>
      </div>

      <!-- Triggered Rules -->
      <div style="margin-bottom: 22px;">
        <h3 style="font-size: 15px; color: #f1f5f9; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;">
          <span style="color: #06b6d4;">◆</span> Heuristic Rule Contributions
        </h3>
        {rules_html}
      </div>

      {gsb_html}

      <!-- Actionable Recommendations -->
      <div style="margin-top: 24px; background: rgba(30, 41, 59, 0.5); border-radius: 8px; padding: 16px; border: 1px solid rgba(255,255,255,0.06);">
        <h3 style="font-size: 15px; color: #f8fafc; margin-top: 0; margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">
          <span style="color: #10b981;">🛡</span> Recommended Security Actions
        </h3>
        <ul style="margin: 0; padding-left: 20px; color: #94a3b8; font-size: 13px; line-height: 1.6;">
          {''.join(f"<li style='margin-bottom: 4px;'>{rec}</li>" for rec in recommendations)}
        </ul>
      </div>

      <!-- Footer Disclaimer -->
      <div style="margin-top: 24px; padding-top: 14px; border-top: 1px solid rgba(255,255,255,0.08); font-size: 11px; color: #64748b; text-align: center;">
        Generated by PhishGuard Threat Intelligence Platform &bull; VTU INS Project Demonstration &bull; Heuristic and intelligence based assessment
      </div>
    </div>
    """

def build_multi_report_html(results):
    sections = []
    for r in results:
        sections.append(build_report_html(
            r["url"],
            r["score"],
            r["verdict"],
            r["triggered_rules"],
            r.get("google_safe_browsing")
        ))

    return f"""
    <div style="background: #020617; padding: 20px; min-height: 100vh;">
      <div style="max-width: 850px; margin: 0 auto 20px; text-align: center; color: #e2e8f0;">
        <h1 style="font-size: 24px; font-weight: bold; color: #06b6d4; margin-bottom: 4px;">PhishGuard Batch Scan Report</h1>
        <p style="color: #94a3b8; font-size: 14px;">Total URLs Evaluated: {len(results)}</p>
      </div>
      <div style="display: flex; flex-direction: column; gap: 24px;">
        {''.join(sections)}
      </div>
    </div>
    """
