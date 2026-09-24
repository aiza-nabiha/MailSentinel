import { useState } from "react";

export default function RelayPath({ hops }) {
  const [active, setActive] = useState(null);
  const activeHop = active !== null ? hops[active] : null;

  return (
    <>
      <div className="relay-track">
        {hops.map((hop, i) => (
          <div key={i} className={`hop ${active === i ? "active" : ""}`} onClick={() => setActive(i)}>
            <div className="hop-line">{i > 0 && <div className="seg" />}</div>
            <div className={`hop-node ${hop.trusted ? "trusted" : hop.verified ? "solid" : ""}`}>
              {hop.trusted ? "🛡" : i === 0 ? "✉️" : i === hops.length - 1 ? "📥" : "🖥"}
            </div>
            <div className="hop-label">{hop.label}</div>
            <div className="hop-sub">{hop.sub}</div>
            <div className={`hop-badge ${hop.trusted ? "trusted-badge" : "unverified"}`}>
              {hop.trusted ? "verified boundary" : hop.verified ? "" : "unverified"}
            </div>
          </div>
        ))}
      </div>
      {activeHop && (
        <div className="hop-panel">
          <div><div className="field-label">IP</div><div className="field-value">{activeHop.ip}</div></div>
          <div><div className="field-label">Location</div><div className="field-value">{activeHop.location}</div></div>
          <div><div className="field-label">Hosting provider</div><div className="field-value">{activeHop.hosting}</div></div>
          <div><div className="field-label">Notes</div><div className="field-value">{activeHop.note}</div></div>
        </div>
      )}
    </>
  );
}