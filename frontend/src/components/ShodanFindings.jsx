const displayItem = (item) => {
  if (typeof item === "string" || typeof item === "number") return String(item);
  if (item && typeof item === "object")
    return item.port ?? item.name ?? item.cve ?? JSON.stringify(item);
  return String(item);
};

export default function ShodanFindings({ shodan }) {
  if (shodan?.status !== "success") return null;
  const ports = Array.isArray(shodan.ports) ? shodan.ports : [];
  const vulns = Array.isArray(shodan.vulns) ? shodan.vulns : [];
  const notablePorts = Array.isArray(shodan.notable_ports)
    ? shodan.notable_ports
    : [];
  const tags = Array.isArray(shodan.tags) ? shodan.tags : [];
  if (!ports.length && !vulns.length && !notablePorts.length) return null;

  return (
    <section className="section exposed-infrastructure">
      <div className="section-head">
        <div>
          <div className="section-kicker">IP INTELLIGENCE</div>
          <div className="section-title">Exposed Infrastructure</div>
        </div>
      </div>
      <div className="score-categories">
        {ports.length > 0 && (
          <div>
            <small>OPEN PORTS</small>
            <ul>
              {ports.map((item, index) => (
                <li key={`${displayItem(item)}-${index}`}>
                  {displayItem(item)}
                </li>
              ))}
            </ul>
          </div>
        )}
        {notablePorts.length > 0 && (
          <div>
            <small>NOTABLE / RISKY PORTS</small>
            <ul>
              {notablePorts.map((item, index) => (
                <li key={`${displayItem(item)}-${index}`}>
                  {item?.port ?? displayItem(item)}
                  {item?.note ? ` — ${item.note}` : ""}
                </li>
              ))}
            </ul>
          </div>
        )}
        {vulns.length > 0 && (
          <div className="shodan-vulnerabilities">
            <small style={{ color: "var(--high)" }}>KNOWN CVES</small>
            <ul>
              {vulns.map((item, index) => (
                <li
                  key={`${displayItem(item)}-${index}`}
                  style={{ color: "var(--high)" }}
                >
                  {displayItem(item)}
                </li>
              ))}
            </ul>
          </div>
        )}
        {tags.length > 0 && (
          <div>
            <small>SHODAN TAGS</small>
            <strong>{tags.map(displayItem).join(", ")}</strong>
          </div>
        )}
      </div>
    </section>
  );
}
