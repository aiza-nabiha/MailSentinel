import { useState } from "react";

const iconFor = (type) => ({ email: "📧", domain: "🌐", ip: "🖥", nameserver: "🌐", mail_server: "✉️", cname: "⌁", asn: "◈", collapsed_infrastructure_summary: "…" }[type] || "•");

function graphLayout(graph) {
  if (!graph?.nodes?.length) return null;
  const center = { x: 450, y: 220 };
  const emailNodes = graph.nodes.filter((node) => node.node_type === "email");
  const current = emailNodes.find((node) => !node.is_historical) || emailNodes[0];
  const ordered = [current, ...graph.nodes.filter((node) => node.id !== current.id)];
  const nodes = ordered.map((node, index) => {
    if (index === 0) return { id: node.id, ...center, icon: iconFor(node.node_type), label: "This email", core: true };
    const angle = ((index - 1) / Math.max(1, ordered.length - 1)) * Math.PI * 2 - Math.PI / 2;
    const radius = index <= 8 ? 145 : 190;
    return { id: node.id, x: center.x + Math.cos(angle) * radius, y: center.y + Math.sin(angle) * radius, icon: iconFor(node.node_type), label: node.value || node.id, core: false };
  });
  const edges = graph.edges.map((edge) => ({
    a: edge.source, b: edge.target,
    type: edge.relationship === "correlated_email" ? "corroborated" : "verified",
    confidence: edge.confidence || 1,
    reason: edge.relationship === "correlated_email" ? (edge.signals?.[0]?.reason || "Correlated infrastructure") : "Observed in this investigation",
  }));
  return { nodes, edges };
}

export default function CampaignGraph({ nodes, edges, graph }) {
  const [tooltip, setTooltip] = useState(null);
  const liveGraph = graphLayout(graph);
  const displayNodes = liveGraph?.nodes || nodes;
  const displayEdges = liveGraph?.edges || edges;
  const node = (id) => displayNodes.find((n) => n.id === id);

  const colorFor = (type) =>
    type === "verified" ? "var(--primary)" : type === "corroborated" ? "var(--secondary)" : "var(--text2)";
  const dashFor = (type) =>
    type === "corroborated" ? "7 5" : type === "inferred" ? "2 5" : "none";

  return (
    <div className="graph-wrap" style={{ position: "relative" }}>
      <svg viewBox="0 0 900 440" style={{ width: "100%", height: 440 }}>
        {displayEdges.map((e, i) => {
          const a = node(e.a), b = node(e.b);
          return (
            <line
              key={i}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={colorFor(e.type)}
              strokeWidth={e.type === "verified" ? 2 : 1.6}
              strokeDasharray={dashFor(e.type)}
              opacity={e.type === "inferred" ? 0.55 : 0.9}
              style={{ cursor: "pointer" }}
              onMouseMove={(ev) => {
                const rect = ev.target.closest(".graph-wrap").getBoundingClientRect();
                setTooltip({
                  x: ev.clientX - rect.left + 14,
                  y: ev.clientY - rect.top + 10,
                  text: `${e.reason} (${Math.round(e.confidence * 100)}% confidence)`,
                });
              }}
              onMouseLeave={() => setTooltip(null)}
            />
          );
        })}
        {displayNodes.map((n) => (
          <g key={n.id}>
            <circle cx={n.x} cy={n.y} r={n.core ? 30 : 24}
              fill={n.core ? "var(--primary)" : "var(--card)"}
              stroke={n.core ? "var(--primary)" : "var(--border)"} strokeWidth="1.5" />
            <text x={n.x} y={n.y + 6} textAnchor="middle" fontSize={n.core ? 20 : 16}>{n.icon}</text>
            <text x={n.x} y={n.y + (n.core ? 48 : 42)} textAnchor="middle" fontSize="11"
              fontFamily="IBM Plex Mono, monospace" fill="var(--text2)">{n.label}</text>
          </g>
        ))}
      </svg>
      {tooltip && (
        <div style={{
          position: "absolute", left: tooltip.x, top: tooltip.y,
          background: "var(--surface)", border: "1px solid var(--border)",
          padding: "8px 12px", borderRadius: 8, fontSize: 12, maxWidth: 220, pointerEvents: "none",
        }}>
          {tooltip.text}
        </div>
      )}
    </div>
  );
}
