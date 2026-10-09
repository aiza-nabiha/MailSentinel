import { useState } from "react";

export default function RelayPath({ hops }) {
  const [active, setActive] = useState(null);
  const relayHops = Array.isArray(hops) ? hops : [];
  const activeHop = active !== null ? relayHops[active] : null;

  return (
    <>
      <div className="relay-track">
        {relayHops.map((hop, i) => (
          <div
            key={`${hop.label || "hop"}-${i}`}
            className={`hop ${active === i ? "active" : ""}`}
            onClick={() => setActive(i)}
          >
            <div className="hop-line">{i > 0 && <div className="seg" />}</div>
            <div
              className={`hop-node ${hop.reliable ? "reliable" : hop.trusted ? "trusted" : hop.verified ? "solid" : ""}`}
            >
              {hop.trusted
                ? "🛡"
                : hop.reliable
                  ? "◆"
                : i === 0
                  ? "✉️"
                  : i === relayHops.length - 1
                    ? "📥"
                    : "🖥"}
            </div>
            <div className="hop-label">{hop.label}</div>
            <div className="hop-sub">{hop.sub}</div>
            <div className="hop-meta">
              <div><span>IP</span><strong>{hop.ip || "Not available"}</strong></div>
              <div><span>Location</span><strong>{hop.location || "Not available"}</strong></div>
              <div><span>Hosting</span><strong>{hop.hosting || "Not available"}</strong></div>
            </div>
            <div
              className={`hop-badge ${hop.reliable ? "reliable-badge" : hop.trusted ? "trusted-badge" : "unverified"}`}
            >
              {hop.reliable
                ? "earliest reliable node"
                : hop.trusted
                ? "verified boundary"
                : hop.verified
                  ? ""
                  : "unverified"}
            </div>
          </div>
        ))}
      </div>
      {activeHop && (
        <div className="hop-panel">
          <div>
            <div className="field-label">IP</div>
            <div className="field-value">{activeHop.ip || "Not available"}</div>
          </div>
          <div>
            <div className="field-label">Forward hostname</div>
            <div className="field-value">{activeHop.sub || "Not available"}</div>
          </div>
          {activeHop.reverseDns && (
            <div>
              <div className="field-label">Reverse DNS</div>
              <div className="field-value">{activeHop.reverseDns}</div>
            </div>
          )}
          <div>
            <div className="field-label">Location</div>
            <div className="field-value">{activeHop.location || "Not available"}</div>
          </div>
          <div>
            <div className="field-label">Hosting provider</div>
            <div className="field-value">{activeHop.hosting || "Not available"}</div>
          </div>
          <div>
            <div className="field-label">Notes</div>
            <div className="field-value">{activeHop.note || "Not available"}</div>
          </div>
          {activeHop.trustedReasons?.length > 0 && (
            <div>
              <div className="field-label">Why this hop was trusted</div>
              <ul className="trusted-reasons">
                {activeHop.trustedReasons.map((reason, index) => (
                  <li key={`${reason}-${index}`}>{reason}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </>
  );
}
