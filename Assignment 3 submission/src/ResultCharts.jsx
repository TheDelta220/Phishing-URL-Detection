import { useEffect, useState } from "react";
import { API_URL, getSessionId } from "./session.js";
import "./ResultCharts.css";


function describeUrl(raw) {
  const text = raw.trim();
  const lower = text.toLowerCase();
  const hasScheme = /^https?:\/\//i.test(text);
  let host = "";
  try {
    host = new URL(hasScheme ? text : `http://${text}`).hostname;
  } catch {
    host = "";
  }
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
  const subdomains = isIp ? 0 : Math.max(0, host.split(".").filter(Boolean).length - 2);
  const keywords = KEYWORDS.filter((k) => lower.includes(k)).length;
  const digitRatio = text.length ? (text.match(/\d/g) || []).length / text.length : 0;
  const special = (text.match(/[^a-z0-9]/gi) || []).length;
  const https = lower.startsWith("https://");
  const letter_count = (text.match(/[a-z]/gi) || []).length;

  return [
    { key: "length", label: "URL length",
      value: text.length, 
      risk: text.length > 75, 
      hint: "how long the URL is" 
    },
    { key: "https", 
        label: "HTTPS", 
        value: hasScheme ? (https ? "Yes" : "No") : "Not given", 
        risk: hasScheme && !https, 
        hint: "Does it use HTTPS?" },
    { key: "ip", 
        label: "IP hostname", 
        value: isIp ? "Yes" : "No",
        risk: isIp, 
        hint: "Does it use an IP address instead of a domain name?" },
    { key: "sub", 
        label: "Subdomains", 
        value: subdomains, 
        risk: subdomains >= 3, 
        hint: "Does it contain many subdomains?" },
    { key: "kw", 
        label: "Suspicious keywords", 
        value: keywords, 
        risk: keywords >= 2, 
        hint: "Does it contain suspicious keywords?" },
    { key: "digits", 
        label: "Digit ratio", 
        value: digitRatio.toFixed(2), 
        risk: digitRatio > 0.2, 
        hint: "Does it have a high ratio of digits?" },
    { key: "special", 
        label: "Special characters", 
        value: special, 
        risk: special >= 12, 
        hint: "Does it contain many special characters?" },
    { key: "letter_count",
        label: "Letter Count", 
        value: letter_count, 
        risk: letter_count < 5, 
        hint: "how many letters are in the URL?" },
  
  ];
}

export function UrlFeatures({ url }) {
  const [tip, setTip] = useState("");
  const features = describeUrl(url);
  return (
    <figure className="insight">
      <figcaption className="insight-title">Features of the submitted URL</figcaption>
      <div className="features" role="list">
        {features.map((f) => (
          <div
            key={f.key}
            role="listitem"
            tabIndex={0}
            title={f.hint}
            className={`feature ${f.risk ? "risk" : ""}`}
            onMouseEnter={() => setTip(`${f.label}: ${f.hint}`)}
            onFocus={() => setTip(`${f.label}: ${f.hint}`)}
            onMouseLeave={() => setTip("")}
            onBlur={() => setTip("")}
          >
            <span className="feature-label">{f.label}</span>
            <strong>{f.value}</strong>
            {f.risk && <span className="flag">Warning sign</span>}
          </div>
        ))}
      </div>
      <p className="insight-note" aria-live="polite">
        {tip || "Hover or focus a tile for an explanation."}
      </p>
      <p className="insight-note">
        These describe the URL text. The model scores the URL's text patterns, so they do not explain the score directly.
      </p>
    </figure>
  );
}

const W = 430, H = 200, L = 42, R = 12, T = 28, B = 34;
const plotW = W - L - R;
const plotH = H - T - B;
const y = (v) => T + plotH * (1 - v / 100);
const shortUrl = (u) => (u.length > 40 ? `${u.slice(0, 40)}…` : u);

export function SessionHistory({ currentId }) {
  const [items, setItems] = useState(null);
  const [error, setError] = useState("");
  const [tip, setTip] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_URL}/api/history?limit=8`, { headers: { "X-Session-ID": getSessionId() } })
      .then((res) => {
        if (!res.ok) throw new Error("bad response");
        return res.json();
      })
      .then((data) => {
        if (!cancelled) setItems([...data.items].reverse()); // oldest first
      })
      .catch(() => {
        if (!cancelled) setError("Couldn't load your history.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  let body;
  if (error) {
    body = <p className="insight-note" role="alert">{error}</p>;
  } else if (!items) {
    body = <p className="insight-note">Loading your history…</p>;
  } else if (!items.length) {
    body = <p className="insight-note">No checks yet.</p>;
  } else {
    const step = plotW / items.length;
    const barW = Math.min(44, step * 0.6);
    body = (
      <>
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Trust score of your most recent checks">
          {[0, 25, 50, 75, 100].map((v) => (
            <g key={v}>
              <line className="hist-grid" x1={L} x2={W - R} y1={y(v)} y2={y(v)} />
              <text className="hist-axis" x={L - 8} y={y(v)} textAnchor="end" dominantBaseline="central">{v}</text>
            </g>
          ))}
          {items.map((it, i) => {
            const trust = Math.round((1 - it.phishing_probability) * 100);
            const bad = it.verdict === "phishing";
            const cx = L + step * i + step / 2;
            const text = `#${i + 1} ${shortUrl(it.url)}: ${bad ? "Phishing" : "Looks legitimate"}, trust score ${trust}`;
            return (
              <g key={it.id} tabIndex={0} className="hist-group" onMouseEnter={() => setTip(text)} onFocus={() => setTip(text)} onMouseLeave={() => setTip("")} onBlur={() => setTip("")}>
                <title>{text}</title>
                <rect
                  className={`hist-bar ${bad ? "bad" : "good"} ${it.id === currentId ? "current" : ""}`}
                  x={cx - barW / 2}
                  y={y(trust)}
                  width={barW}
                  height={Math.max(1, y(0) - y(trust))}
                  rx="4"
                />
                <text className="hist-value" x={cx} y={y(trust) - 6} textAnchor="middle">{trust}</text>
                <text className="hist-axis" x={cx} y={H - 14} textAnchor="middle">#{i + 1}</text>
              </g>
            );
            
          })}
          <text className="hist-axis" x={L + plotW / 2} y={H - 1} textAnchor="middle">Check (oldest to newest)</text>
        </svg>
        <ul className="legend">
          <li><span className="swatch good" /> Looks legitimate</li>
          <li><span className="swatch bad" /> Phishing</li>
          <li><span className="swatch current" /> This check</li>
        </ul>
        <p className="insight-note" aria-live="polite">{tip || "Hover or focus a bar for details."}</p>
      </>
    );
  }

  return (
    <figure className="insight">
      <figcaption className="insight-title">Your recent checks: trust score for each request (0 to 100)</figcaption>
      {body}
    </figure>
  );
}

const KEYWORDS = [
  "login",
  "verify",
  "secure",
  "update",
  "bank",
  "paypal",
  "confirm",
  "password",
  "signin",
  "access",
  "security",
  "portal",
  "company",
  "admin",
  "credential",
  "identity",
  "privilege",
  "token",
  "validation",
  "assurance",
  "availability",
  "confidentiality",
  "integrity",
  "privacy",
  "safety",
  "trust",
  "verification",
  "lock",
  "biometrics",
  "authorize",
  "session",
  "profile",
  "support",
  "notify",
  "notification",
  "transaction",
  "validate",
  "confirmation",
  "manager",
  "assistant",
  "dashboard",
  "information",
  "communication",
  "finance",
  "maintenance",
  "customer",
  "invoice",
  "billing",
  "subscription",
  "order",
  "shipment",
  "purchase",
  "alert",
  "billinginfo",
  "receipt",
  "accountinfo",
  "payment",
  "invoiceinfo",
  "orderinfo"
];