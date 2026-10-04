import { useState } from "react";
import { correlationSignalLabel } from "../utils/mapApiResponse";

const iconFor = (type) =>
  ({
    email: "📧",
    domain: "🌐",
    ip: "🖥",
    nameserver: "🌐",
    mail_server: "✉️",
    cname: "⌁",
    asn: "◈",
    collapsed_infrastructure_summary: "…",
  })[type] || "•";

// For a normal node, `value` is a plain string (a domain, IP, etc.).
// For a "collapsed_infrastructure_summary" node, the backend puts a
// COUNT DICT there instead -- e.g. {mail_server: 3, nameserver: 2},
// one entry per infrastructure kind that got collapsed (too many to
// show individually, or known large providers like Google/Cloudflare
// that are excluded from correlation). Rendering that dict directly
// as a label crashed with "Objects are not valid as a React child"
// (minified error #31) -- this turns it into readable text instead.
const nodeLabel = (node) => {
  if (node.value && typeof node.value === "object") {
    const parts = Object.entries(node.value).map(
      ([kind, count]) =>
        `${count} ${kind.replace(/_/g, " ")}${count === 1 ? "" : "s"}`,
    );
    return parts.length ? parts.join(", ") : "Additional infrastructure";
  }
  return node.value || node.id;
};

function graphLayout(graph) {
  if (!graph?.nodes?.length) return null;
  const center = { x: 450, y: 220 };
  const emailNodes = graph.nodes.filter((node) => node.node_type === "email");
  const current =
    emailNodes.find((node) => !node.is_historical) || emailNodes[0];
  if (!current) return null;
  const rest = graph.nodes.filter((node) => node.id !== current.id);

  // Cap how many nodes we actually draw -- beyond this the ring layout
  // can't fit both circles and labels without overlapping, regardless
  // of radius. Keep the highest-confidence edges' nodes, collapse the
  // rest into one summary node.
  const MAX_VISIBLE = 12;
  const edgeConfidence = (nodeId) =>
    Math.max(
      0,
      ...graph.edges
        .filter((edge) => edge.source === nodeId || edge.target === nodeId)
        .map((edge) => edge.confidence || 0),
    );
  const sorted = [...rest].sort(
    (a, b) => edgeConfidence(b.id) - edgeConfidence(a.id),
  );
  const visible = sorted.slice(0, MAX_VISIBLE);
  const overflow = sorted.slice(MAX_VISIBLE);

  const ordered = [current, ...visible];
  if (overflow.length) {
    ordered.push({
      id: "_overflow_",
      node_type: "collapsed_infrastructure_summary",
      value: { "related indicator": overflow.length },
    });
  }

  const labelMargin = 45;
  const maxRadiusX = center.x - 70 - labelMargin;
  const maxRadiusY = center.y - 70 - labelMargin;
  const baseRadius = ordered.length > 9 ? 150 : 120;
  const radius = Math.max(60, Math.min(baseRadius, maxRadiusX, maxRadiusY));
  const nodes = ordered.map((node, index) => {
    if (index === 0)
      return {
        id: node.id,
        ...center,
        icon: iconFor(node.node_type),
        label: "This email",
        core: true,
      };
    const angle =
      ((index - 1) / Math.max(1, ordered.length - 1)) * Math.PI * 2 -
      Math.PI / 2;
    return {
      id: node.id,
      x: center.x + Math.cos(angle) * radius,
      y: center.y + Math.sin(angle) * radius,
      icon: iconFor(node.node_type),
      label: nodeLabel(node),
      core: false,
    };
  });
  const edges = graph.edges
    .filter(
      (edge) =>
        nodes.some((node) => node.id === edge.source) &&
        nodes.some((node) => node.id === edge.target),
    )
    .map((edge) => ({
      a: edge.source,
      b: edge.target,
      type:
        edge.relationship === "correlated_email" ? "corroborated" : "verified",
      confidence: edge.confidence || 1,
      reason:
        edge.relationship === "correlated_email"
          ? edge.signals?.length
            ? edge.signals.map(correlationSignalLabel).join(", ")
            : "Correlated infrastructure"
          : "Observed in this investigation",
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
    type === "verified"
      ? "var(--primary)"
      : type === "corroborated"
        ? "var(--secondary)"
        : "var(--text2)";
  const dashFor = (type) =>
    type === "corroborated" ? "7 5" : type === "inferred" ? "2 5" : "none";

  return (
    <div className="graph-wrap" style={{ position: "relative" }}>
      <svg viewBox="0 0 900 420" style={{ width: "100%", height: 420 }}>
        {displayEdges.map((e, i) => {
          const a = node(e.a),
            b = node(e.b);
          if (!a || !b) return null;
          return (
            <line
              key={i}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={colorFor(e.type)}
              strokeWidth={e.type === "verified" ? 2 : 1.6}
              strokeDasharray={dashFor(e.type)}
              opacity={e.type === "inferred" ? 0.55 : 0.9}
              style={{ cursor: "pointer" }}
              onMouseMove={(ev) => {
                const rect = ev.target
                  .closest(".graph-wrap")
                  .getBoundingClientRect();
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
            <circle
              cx={n.x}
              cy={n.y}
              r={n.core ? 30 : 24}
              fill={n.core ? "var(--primary)" : "var(--card)"}
              stroke={n.core ? "var(--primary)" : "var(--border)"}
              strokeWidth="1.5"
            />
            <text
              x={n.x}
              y={n.y + 6}
              textAnchor="middle"
              fontSize={n.core ? 20 : 16}
            >
              {n.icon}
            </text>
            <text
              x={n.x}
              y={n.y + (n.core ? 48 : 42)}
              textAnchor="middle"
              fontSize="11"
              fontFamily="IBM Plex Mono, monospace"
              fill="var(--text2)"
            >
              {n.label}
            </text>
          </g>
        ))}
      </svg>
      {tooltip && (
        <div
          style={{
            position: "absolute",
            left: tooltip.x,
            top: tooltip.y,
            background: "var(--surface)",
            border: "1px solid var(--border)",
            padding: "8px 12px",
            borderRadius: 8,
            fontSize: 12,
            maxWidth: 220,
            pointerEvents: "none",
          }}
        >
          {tooltip.text}
        </div>
      )}
    </div>
  );
}
