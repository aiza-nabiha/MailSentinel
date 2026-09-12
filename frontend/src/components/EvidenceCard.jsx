import { useState } from "react";

export default function EvidenceCard({ reason }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="evidence-card" onClick={() => setOpen(!open)}>
      <div className="evidence-top">
        <div className="evidence-icon">{reason.icon}</div>
        <div className="evidence-title">{reason.title}</div>
        <div className="evidence-source">{reason.source}</div>
      </div>
      {open && <div className="evidence-detail">{reason.detail}</div>}
    </div>
  );
}