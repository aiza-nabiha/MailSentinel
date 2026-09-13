import { useEffect, useState } from "react";
import InvestigationReportPage from "./pages/InvestigationReportPage";

const analysisSteps = ["Parsing email", "Extracting indicators", "Checking authentication", "Analyzing infrastructure", "Checking reputation", "Correlating campaigns", "Computing risk"];
const Mark = () => <div className="brand-mark" aria-hidden="true">⌁</div>;

function Topbar({ theme, setTheme, onHome, view, setView }) {
  return <header className="topbar"><button className="brand" onClick={onHome}><Mark /><span className="brand-name">Mail<span>Sentinel</span></span></button><nav className="top-nav"><button className={view === "report" ? "active" : ""} onClick={() => setView("report")}>Investigations</button><button className={view === "history" ? "active" : ""} onClick={() => setView("history")}>History</button><button className={view === "settings" ? "active" : ""} onClick={() => setView("settings")}>Settings</button></nav><button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}><span>{theme === "dark" ? "☀" : "☾"}</span><span>{theme === "dark" ? "Light" : "Dark"}</span></button></header>;
}
const NetworkBackdrop = () => <div className="network-backdrop" aria-hidden="true"><i /><i /><i /><i /><b /><b /><b /><b /></div>;

function Landing({ onAnalyze }) {
  const [dragging, setDragging] = useState(false), [fileName, setFileName] = useState(""), [error, setError] = useState(""), [selectedFile, setSelectedFile] = useState(null);
  const choose = (file) => { if (!file) return; if (!file.name.toLowerCase().endsWith(".eml")) { setError("MailSentinel needs the original .eml message to retain forensic headers."); return; } setError(""); setFileName(file.name); setSelectedFile(file); };
  return <main className="landing"><NetworkBackdrop /><section className="command-hero"><div className="hero-copy"><div className="eyebrow"><span /> EMAIL THREAT FORENSICS</div><h1>See the attack<br /><em>behind</em> the email.</h1><p>MailSentinel turns a suspicious message into a defensible investigation—tracing authentication, infrastructure and campaign links in one live workspace.</p><div className="hero-actions"><button className="hero-primary" onClick={() => onAnalyze(null)}>Explore a live investigation <b>→</b></button><button className="hero-secondary" onClick={() => document.getElementById("upload")?.scrollIntoView({ behavior: "smooth" })}>Analyze an .eml</button></div><div className="trust-strip"><span><b>7</b> intelligence checks</span><i /><span><b>3</b> evidence confidence levels</span></div></div><div className="hero-visual"><img src="/forensics-hero.png" alt="Abstract forensic data network" /><div className="visual-chip chip-top">● AUTHENTICATION <b>FAILED</b></div><div className="visual-chip chip-bottom">CAMPAIGN MATCH <b>91% confidence</b></div></div></section><section className="signal-band"><div><small>01 / INGEST</small><strong>Preserve headers</strong><span>Original .eml evidence</span></div><div><small>02 / ANALYZE</small><strong>Expose signals</strong><span>Explainable threat score</span></div><div><small>03 / CORRELATE</small><strong>Connect campaigns</strong><span>Infrastructure graph</span></div></section><section className="upload-section" id="upload"><div className="upload-copy"><div className="eyebrow"><span /> START AN INVESTIGATION</div><h2>Bring the original.<br />Follow the evidence.</h2><p>Upload an exported email to retain the headers that explain where it actually came from.</p><div className="mini-evidence"><span>✦</span><p><b>No black-box verdicts.</b><br />Every risk signal connects to underlying evidence.</p></div></div><label className={`drop-zone ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); choose(e.dataTransfer.files[0]); }}><input type="file" accept=".eml,message/rfc822" onChange={(e) => choose(e.target.files[0])} /><div className="upload-orb">↑</div><strong>{fileName || "Drop a .eml file here"}</strong><span>{fileName ? "Ready for investigation" : "or click to browse from your device"}</span>{error && <small className="upload-error">{error}</small>}<button type="button" className="analyze-button" onClick={(e) => { e.preventDefault(); onAnalyze(selectedFile); }}>Analyze email <b>→</b></button><button type="button" className="sample-button" onClick={(e) => { e.preventDefault(); onAnalyze(null); }}>Try a sample investigation</button></label></section><section className="why-section"><div className="section-kicker">INTELLIGENCE YOU CAN DEFEND</div><h2>One message.<br /><em>Every</em> connection.</h2><div className="feature-grid"><article><span>◈</span><h3>Explainable risk</h3><p>Show the exact content, URL and authentication signals that make the decision.</p></article><article><span>⌁</span><h3>Forensic relay trace</h3><p>Find the trusted boundary and distinguish what is known from what was claimed.</p></article><article><span>◎</span><h3>Campaign intelligence</h3><p>See verified infrastructure links separately from corroborated and inferred patterns.</p></article></div></section></main>;
}

function Analyzing({ fileName, onDone }) {
  const [step, setStep] = useState(0);
  useEffect(() => { const id = setInterval(() => setStep((value) => { if (value === analysisSteps.length - 1) { clearInterval(id); setTimeout(onDone, 500); return value; } return value + 1; }), 420); return () => clearInterval(id); }, [onDone]);
  return <main className="analysis-screen"><NetworkBackdrop /><div className="analysis-card"><div className="analysis-radar"><span /><span /><span /><b>⌁</b></div><div className="eyebrow"><span /> INVESTIGATION IN PROGRESS</div><h1>Reading the signals.</h1><p className="analysis-file">{fileName}</p><ol>{analysisSteps.map((item, index) => <li className={index < step ? "done" : index === step ? "current" : ""} key={item}><span>{index < step ? "✓" : index === step ? "◌" : "·"}</span>{item}<small>{index < step ? "complete" : index === step ? "running" : "queued"}</small></li>)}</ol></div></main>;
}

function History({ openReport, newInvestigation }) { const items = [["HIGH", "fake-bank.xyz", "87", "Today · 09:14"], ["MEDIUM", "parcel-delivery.support", "54", "Yesterday · 16:42"], ["SAFE", "accounts.google.com", "12", "Sep 10 · 11:08"]]; return <main className="workspace-page"><div className="workspace-heading"><div><div className="eyebrow"><span /> INVESTIGATION ARCHIVE</div><h1>Recent investigations</h1><p>Review historic email decisions and their connected infrastructure.</p></div><button className="analyze-button" onClick={newInvestigation}>+ New investigation</button></div><div className="archive-list">{items.map(([level, domain, score, time]) => <button className="archive-row" key={domain} onClick={openReport}><span className={`risk-pill ${level.toLowerCase()}`}>{level}</span><strong>{domain}</strong><span className="archive-time">{time}</span><span className="archive-score">{score}<small>/100</small></span><span>→</span></button>)}</div></main>; }

function Settings() { const [saved, setSaved] = useState(false); return <main className="workspace-page settings-page"><div className="workspace-heading"><div><div className="eyebrow"><span /> WORKSPACE</div><h1>Investigation settings</h1><p>Configure how MailSentinel presents and retains analysis results.</p></div></div><div className="settings-card"><div><h2>Analysis endpoint</h2><p>Connect this workspace to the MailSentinel backend when it is running.</p></div><label>Endpoint<input defaultValue="http://localhost:5001/analyze" /></label><label className="switch-row">Keep investigations in this browser <input type="checkbox" defaultChecked /></label><button className="analyze-button" onClick={() => setSaved(true)}>{saved ? "✓ Settings saved" : "Save settings"}</button></div></main>; }

export default function App() {
  const [theme, setTheme] = useState("dark"), [view, setView] = useState("landing"), [fileName, setFileName] = useState("");
  const [investigationData, setInvestigationData] = useState(null);
  useEffect(() => document.documentElement.setAttribute("data-theme", theme), [theme]);
  const home = () => setView("landing");

  const start = async (file) => {
    setFileName(file?.name || "sample-phishing-email.eml");
    setView("analyzing");
    try {
      const body = file
        ? { raw_eml: await file.text(), user_id: "demo@gmail.com" }
        : { eml_path: "test_emails/example.eml", user_id: "demo@gmail.com" };
      const response = await fetch(`${import.meta.env.VITE_API_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": import.meta.env.VITE_API_KEY },
        body: JSON.stringify(body),
      });
      const result = await response.json();
      setInvestigationData(result);
    } catch (err) {
      console.error("Analysis failed:", err);
      setInvestigationData(null);
    }
  };

  return (
    <div className="app-shell">
      <Topbar theme={theme} setTheme={setTheme} onHome={home} view={view} setView={setView} />
      {view === "landing" && <Landing onAnalyze={start} />}
      {view === "analyzing" && <Analyzing fileName={fileName} onDone={() => setView("report")} />}
      {view === "report" && <InvestigationReportPage apiResponse={investigationData} onNewInvestigation={home} />}
      {view === "history" && <History openReport={() => setView("report")} newInvestigation={home} />}
      {view === "settings" && <Settings />}
    </div>
  );
}