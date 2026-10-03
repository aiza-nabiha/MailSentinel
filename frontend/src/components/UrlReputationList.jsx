const getStatus = (item) => {
  if (item.found_on_lists.length > 0) return "listed";
  const reputation = String(item.reputation || "").toLowerCase();
  return /suspicious|malicious|phishing|threat/.test(reputation)
    ? "suspicious"
    : "clean";
};

const statusColors = {
  clean: {
    color: "var(--safe)",
    background: "color-mix(in srgb, var(--safe) 12%, white)",
  },
  suspicious: {
    color: "var(--medium)",
    background: "color-mix(in srgb, var(--medium) 12%, white)",
  },
  listed: {
    color: "var(--high)",
    background: "color-mix(in srgb, var(--high) 12%, white)",
  },
};

export default function UrlReputationList({ items }) {
  if (!items.length)
    return (
      <div className="empty-state">
        No URL reputation data was returned for this investigation.
      </div>
    );

  return (
    <ul className="url-reputation-list">
      {items.map((item, index) => {
        const status = getStatus(item);
        return (
          <li key={`${item.url || "url"}-${index}`}>
            <span className="mono">{item.url || "URL unavailable"}</span>
            <span className="status-pill" style={statusColors[status]}>
              {status}
            </span>
            {item.found_on_lists.length > 0 && (
              <small>Found on: {item.found_on_lists.join(", ")}</small>
            )}
          </li>
        );
      })}
    </ul>
  );
}
