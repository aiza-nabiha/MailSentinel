import LoginPage from "./pages/LoginPage";
import { useEffect, useState } from "react";
import InvestigationReportPage from "./pages/InvestigationReportPage";
import { analyzeEmail, getHistory, getInvestigation } from "./utils/api";

const analysisSteps = ["Parsing email", "Extracting indicators", "Checking authentication", "Analyzing infrastructure", "Checking reputation", "Correlating campaigns", "Computing risk"];
const Mark = () => <div className="brand-mark" aria-hidden="true">⌁</div>;

function Topbar({ theme, setTheme, onHome, view, setView }) {
  return <header className="topbar"><button className="brand" onClick={onHome}><Mark /><span className="brand-name">Mail<span>Sentinel</span></span></button><nav className="top-nav"><button className={view === "report" ? "active" : ""} onClick={() => setView("report")}>Investigations</button><button className={view === "history" ? "active" : ""} onClick={() => setView("history")}>History</button></nav>
    <button className="theme-toggle"
      onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
    >
      <span>{theme === "dark" ? "☀" : "☾"}</span>
      <span>{theme === "dark" ? "Light" : "Dark"}</span>
    </button>
    <button 
      className="theme-toggle"
      onClick={() => setView("login")}
    > 
      LOGIN  
    </button> 
    </header>;
}
const NetworkBackdrop = () => <div className="network-backdrop" aria-hidden="true"><i /><i /><i /><i /><b /><b /><b /><b /></div>;

function Landing({ onAnalyze, analysisError }) {
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const choose = (file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".eml")) {
      setError("Upload an .eml file to preserve the original forensic headers.");
      return;
    }
    setError("");
    setFileName(file.name);
    setSelectedFile(file);
  };

  return <main className="landing modern-home">
    <section className="modern-hero">
      <div className="modern-hero-copy">
        <div className="modern-eyebrow"><span /> EMAIL THREAT INTELLIGENCE</div>
        <h1>Make sense<br />of the <em>signals.</em></h1>
        <p>Trace suspicious email from the original message to the infrastructure behind it. One clear investigation, with every finding explained.</p>
        <div className="modern-actions">
          <button className="modern-primary" onClick={() => document.getElementById("upload")?.scrollIntoView({ behavior: "smooth" })}>Analyze an email <b>↗</b></button>
          <button className="modern-secondary" onClick={() => onAnalyze(null)}>Explore a sample <span>→</span></button>
        </div>
        <div className="modern-assurance"><span>✓</span> Original headers preserved <i /> Explainable findings <i /> Connected evidence</div>
      </div>
      <div className="modern-visual">
        <img src="/forensics-hero.png" alt="A connected map of digital infrastructure" />
        <div className="modern-visual-shade" />
        <div className="modern-visual-top"><span>LIVE INVESTIGATION VIEW</span><b><i /> READY</b></div>
        <div className="modern-visual-card"><small>ANALYSIS PATH</small><strong>Email <i>→</i> Domain <i>→</i> Network</strong><span>One connected view of the evidence</span></div>
        <div className="modern-visual-index">01 <span>/ 04</span></div>
      </div>
      <div className="modern-hero-foot"><span>MAILSENTINEL / SECURITY, CONNECTED</span><a href="#capabilities">Discover the platform ↓</a></div>
    </section>

    <section className="modern-capabilities" id="capabilities">
      <div className="modern-section-heading"><div><div className="modern-eyebrow"><span /> A CLEARER VIEW OF EVERY MESSAGE</div><h2>Find the story<br />behind the <em>email.</em></h2></div><p>Move beyond a single risk score. MailSentinel connects the signals, evidence, and infrastructure that explain what happened.</p></div>
      <div className="modern-feature-grid">
        <article><span className="modern-feature-no">01 / AUTHENTICITY</span><div className="modern-feature-icon">◎</div><h3>Verify the sender</h3><p>Review SPF, DKIM, DMARC, and the trusted relay path to understand who sent the message.</p><a href="#upload">Inspect the headers <b>↗</b></a></article>
        <article><span className="modern-feature-no">02 / INFRASTRUCTURE</span><div className="modern-feature-icon">⌁</div><h3>Trace the route</h3><p>Follow links, domains, IP addresses, and hosting details from one connected investigation.</p><a href="#upload">Trace an email <b>↗</b></a></article>
        <article><span className="modern-feature-no">03 / CAMPAIGNS</span><div className="modern-feature-icon">⟷</div><h3>Connect the cases</h3><p>Reveal shared infrastructure and related investigations when matching signals are found.</p><a href="#upload">Explore correlation <b>↗</b></a></article>
      </div>
    </section>

    <section className="modern-process"><div className="modern-process-title"><div className="modern-eyebrow"><span /> FROM INBOX TO INFRASTRUCTURE</div><h2>One message.<br /><em>Full context.</em></h2></div><div className="modern-process-steps"><div><b>01</b><strong>Preserve</strong><span>Start with the original .eml evidence.</span></div><div><b>02</b><strong>Analyze</strong><span>Inspect content, identity, and infrastructure.</span></div><div><b>03</b><strong>Understand</strong><span>See the verdict, reasons, and connections.</span></div></div></section>

    <section className="modern-upload" id="upload"><div className="modern-upload-copy"><div className="modern-eyebrow"><span /> START AN INVESTIGATION</div><h2>Bring the original.<br /><em>Follow the evidence.</em></h2><p>Choose a suspicious email saved in .eml format. MailSentinel preserves its headers as it builds your investigation.</p><div className="modern-private"><span>◈</span> Built for evidence you can inspect</div></div><label className={`modern-dropzone ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); choose(e.dataTransfer.files[0]); }}><input type="file" accept=".eml,message/rfc822" onChange={(e) => choose(e.target.files[0])} /><div className="modern-upload-icon">↑</div><strong>{fileName || "Drop your .eml file here"}</strong><span>{fileName ? "Ready to analyze" : "or browse files on your device"}</span>{(error || analysisError) && <small className="upload-error">{error || analysisError}</small>}<button type="button" className="modern-primary" onClick={(e) => { e.preventDefault(); onAnalyze(selectedFile); }}>Analyze email <b>↗</b></button><small className="modern-file-note">SUPPORTED FORMAT <b>.EML</b></small></label></section>
    <footer className="modern-footer"><div><span className="modern-footer-mark">⌁</span><b>MailSentinel</b></div><span>EMAIL THREAT INTELLIGENCE</span><button onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>Back to top ↑</button></footer>
  </main>;
}

function Analyzing({ fileName }) {
  const [step, setStep] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setStep((value) => (value < analysisSteps.length - 1 ? value + 1 : value)), 420);
    return () => clearInterval(id);
  }, []);
  return <main className="analysis-screen"><NetworkBackdrop /><div className="analysis-card"><div className="analysis-radar"><span /><span /><span /><b>⌁</b></div><div className="eyebrow"><span /> INVESTIGATION IN PROGRESS</div><h1>Reading the signals.</h1><p className="analysis-file">{fileName}</p><ol>{analysisSteps.map((item, index) => <li className={index < step ? "done" : index === step ? "current" : ""} key={item}><span>{index < step ? "✓" : index === step ? "◌" : "·"}</span>{item}<small>{index < step ? "complete" : index === step ? "running" : "queued"}</small></li>)}</ol></div></main>;
}

function History({ openReport, newInvestigation, userId }) {
  const [items, setItems] = useState([]), [error, setError] = useState(""), [loading, setLoading] = useState(true);
  useEffect(() => { let active = true; getHistory(userId).then((data) => active && setItems(data.emails || [])).catch((err) => active && setError(err.message)).finally(() => active && setLoading(false)); return () => { active = false; }; }, [userId]);
  return <main className="workspace-page"><div className="workspace-heading"><div><div className="eyebrow"><span /> INVESTIGATION ARCHIVE</div><h1>Recent investigations</h1><p>Review historic email decisions and their connected infrastructure.</p></div><button className="analyze-button" onClick={newInvestigation}>+ New investigation</button></div><div className="archive-list">{loading && <p>Loading investigations…</p>}{error && <p className="upload-error">{error}</p>}{!loading && !error && !items.length && <p>No investigations have been created for this workspace yet.</p>}{items.map((item) => <button className="archive-row" key={item.email_id} onClick={() => openReport(item.email_id)}><span className={`risk-pill ${String(item.verdict || "safe").toLowerCase()}`}>{item.verdict || "safe"}</span><strong>{item.subject || item.email_id}</strong><span className="archive-time">{item.ingested_at || "Date unavailable"}</span><span className="archive-score">{item.overall_risk_score ?? "—"}<small>/100</small></span><span>→</span></button>)}</div></main>;
}

function Settings() {
  const [provider, setProvider] = useState("Gmail");

  return <main className="workspace-page email-test-page">
    <form className="email-test-card" aria-labelledby="email-test-title" onSubmit={(event) => event.preventDefault()}>
      <Mark />
      <div><div className="eyebrow"><span /> SECURE WORKSPACE</div><h1 id="email-test-title">Sign in to MailSentinel</h1></div>
      <div className="provider-list" role="radiogroup" aria-label="Email provider">
        {["Gmail", "Rediffmail", "Yahoo Mail"].map((name) => <label className="provider-option" key={name}>
          <input type="radio" name="provider" value={name} checked={provider === name} onChange={() => setProvider(name)} />
          {name}
        </label>)}
      </div>
      <label className="email-field">Email address<input type="email" placeholder="you@example.com" required /></label>
      <button className="analyze-button" type="submit">Login / Continue</button>
    </form>
  </main>;
}

export default function App() {
  const [theme, setTheme] = useState("dark"), [view, setView] = useState("landing"), [fileName, setFileName] = useState("");
  const [investigationData, setInvestigationData] = useState(null), [analysisError, setAnalysisError] = useState("");
  const userId = import.meta.env.VITE_DEMO_USER_ID || "demo@gmail.com";
  useEffect(() => document.documentElement.setAttribute("data-theme", theme), [theme]);
  const home = () => { setInvestigationData(null); setView("landing"); };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const investigationId = params.get("investigation");
    if (!investigationId) return;

    (async () => {
      setInvestigationData(null);
      setView("analyzing");
      setFileName(investigationId);
      try {
        const result = await getInvestigation(investigationId);
        setInvestigationData(result);
        setView("report");
      } catch (err) {
        console.error("Failed to load investigation:", err);
        setView("landing");
      }
    })();
  }, []);

  const start = async (file) => {
    setAnalysisError("");
    setInvestigationData(null);
    setFileName(file?.name || "sample-phishing-email.eml");
    setView("analyzing");
    try {
      const body = file
        ? { raw_eml: await file.text(), user_id: "demo@gmail.com" }
        : { eml_path: "test_emails/example.eml", user_id: "demo@gmail.com" };
      const result = await analyzeEmail(body);
      setInvestigationData(result);
      setView("report");
    } catch (err) {
      console.error("Analysis failed:", err);
      setAnalysisError(err.message || "Unable to reach the analysis service. Check that the backend is running.");
      setInvestigationData(null);
      setView("landing");
    }
  };

  return (
    <div className="app-shell">
      <Topbar theme={theme} setTheme={setTheme} onHome={home} view={view} setView={setView} />
      {view === "login" && <LoginPage />}
      {view === "landing" && <Landing onAnalyze={start} analysisError={analysisError} />}
      {view === "analyzing" && <Analyzing fileName={fileName} />}
      {view === "report" && <InvestigationReportPage apiResponse={investigationData} onNewInvestigation={home} />}
      {view === "history" && <History openReport={async (id) => { try { setInvestigationData(await getInvestigation(id)); setView("report"); } catch (err) { setAnalysisError(err.message); setView("landing"); } }} newInvestigation={home} userId={userId} />}
      {view === "settings" && <Settings />}
    </div>
  );
}
