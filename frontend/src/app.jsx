import LoginPage from "./pages/LoginPage";
import { useEffect, useState } from "react";
import InvestigationReportPage from "./pages/InvestigationReportPage";
import { analyzeEmail, getHistory, getInvestigation, getCurrentUser, logoutUrl } from "./utils/api";

const analysisSteps = [
  "Parsing email",
  "Extracting indicators",
  "Checking authentication",
  "Analyzing infrastructure",
  "Checking reputation",
  "Correlating campaigns",
  "Computing risk",
];

const Mark = () => (
  <div className="brand-mark" aria-hidden="true">
    ⌁
  </div>
);

function Topbar({ theme, setTheme, onHome, view, setView, user }) {
  return (
    <header className="topbar">
      <button className="brand" onClick={onHome}>
        <Mark />

        <span className="brand-name">
          Mail<span>Sentinel</span>
        </span>
      </button>

      <nav className="top-nav">
        <button
          className={view === "report" ? "active" : ""}
          onClick={() => setView("report")}
        >
          Investigations
        </button>

        <button
          className={view === "history" ? "active" : ""}
          onClick={() => setView("history")}
        >
          History
        </button>
      </nav>

      <div className="topbar-actions">
        <button
          className="theme-toggle"
          onClick={() =>
            setTheme(theme === "dark" ? "light" : "dark")
          }
        >
          <span>{theme === "dark" ? "☀" : "☾"}</span>

          <span>
            {theme === "dark" ? "Light" : "Dark"}
          </span>
        </button>

        {user ? (
          <div className="user-menu">
            <button
              type="button"
              className="profile-avatar"
              title={user.email}
              onClick={() => {
                const menu = document.getElementById("profile-menu");
                if (menu) {
                  menu.style.display =
                    menu.style.display === "block" ? "none" : "block";
                }
              }}
            >
              {user.picture ? (
                <img
                  src={user.picture}
                  alt={user.name || user.email}
                  className="profile-avatar-image"
                />
              ) : (
                user.email?.charAt(0).toUpperCase()
              )}
            </button>

            <div
              id="profile-menu"
              className="profile-menu"
              style={{ display: "none" }}
            >
              <div className="profile-name">{user.name}</div>
              <div className="profile-email">{user.email}</div>

              <button
                type="button"
                onClick={() => {
                  window.location.href = logoutUrl();
                }}
              >
                LOGOUT
              </button>
            </div>
          </div>
        ) : (
          <button
            className="theme-toggle"
            onClick={() => setView("login")}
          >
            LOGIN
          </button>
        )}
      </div>
    </header>
  );
}

const NetworkBackdrop = () => (
  <div className="network-backdrop" aria-hidden="true">
    <i />
    <i />
    <i />
    <i />
    <b />
    <b />
    <b />
    <b />
  </div>
);

function Landing({ onAnalyze, analysisError }) {
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);

  const choose = (file) => {
    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setError(
        "MailSentinel needs the original .eml message to retain forensic headers."
      );
      return;
    }

    setError("");
    setFileName(file.name);
    setSelectedFile(file);
  };

  return (
    <main className="landing">
      <NetworkBackdrop />

      <section className="command-hero product-hero">
        <div className="hero-copy">
          <div className="eyebrow">
            <span /> EMAIL THREAT INTELLIGENCE
          </div>

          <h1>
            Detect the email.
            <br />
            <em>Reconstruct</em> the attack.
          </h1>

          <p>
            Analyze suspicious emails using content intelligence,
            authentication, infrastructure analysis and campaign
            correlation — all from one investigation.
          </p>

          <div className="hero-actions">
            <button
              className="hero-primary"
              onClick={() =>
                document
                  .getElementById("upload")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Upload .EML <b>→</b>
            </button>

            <button
              className="hero-secondary"
              onClick={() => onAnalyze(null)}
            >
              Analyze with Gmail
            </button>
          </div>
        </div>

        <div className="product-preview">
          <div className="preview-top">
            <span className="mono">
              MAILSENTINEL / LIVE ANALYSIS
            </span>
            <span className="preview-dot">●</span>
          </div>

          <div className="preview-verdict">
            <div>
              <small>RISK VERDICT</small>
              <strong>ANALYZE AN EMAIL</strong>
              <span>Investigation data appears here</span>
            </div>

            <div className="preview-score">
              —
              <small>/ 100</small>
            </div>
          </div>

          <div className="preview-path">
            <span>EMAIL</span>
            <b>→</b>
            <span>URL</span>
            <b>→</b>
            <span>DOMAIN</span>
            <b>→</b>
            <span>IP</span>
            <b>→</b>
            <span>ASN</span>
          </div>

          <div className="preview-related">
            <span>◌</span> Related investigations are shown when
            matching infrastructure is found.
          </div>
        </div>
      </section>

      <section className="signal-band">
        <div>
          <small>01 / INGEST</small>
          <strong>Preserve headers</strong>
          <span>Original .eml evidence</span>
        </div>

        <div>
          <small>02 / ANALYZE</small>
          <strong>Expose signals</strong>
          <span>Explainable threat score</span>
        </div>

        <div>
          <small>03 / CORRELATE</small>
          <strong>Connect campaigns</strong>
          <span>Infrastructure graph</span>
        </div>
      </section>

      <section className="upload-section" id="upload">
        <div className="upload-copy">
          <div className="eyebrow">
            <span /> START AN INVESTIGATION
          </div>

          <h2>
            Bring the original.
            <br />
            Follow the evidence.
          </h2>

          <p>
            Upload an exported email to retain the headers that
            explain where it actually came from.
          </p>
        </div>

        <label
          className={`drop-zone ${dragging ? "dragging" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            choose(e.dataTransfer.files[0]);
          }}
        >
          <input
            type="file"
            accept=".eml,message/rfc822"
            onChange={(e) => choose(e.target.files[0])}
          />

          <div className="upload-orb">↑</div>

          <strong>
            {fileName || "Drop a .eml file here"}
          </strong>

          <span>
            {fileName
              ? "Ready for investigation"
              : "or click to browse from your device"}
          </span>

          {(error || analysisError) && (
            <small className="upload-error">
              {error || analysisError}
            </small>
          )}

          <button
            type="button"
            className="analyze-button"
            onClick={(e) => {
              e.preventDefault();
              onAnalyze(selectedFile);
            }}
          >
            Analyze email <b>→</b>
          </button>
        </label>
      </section>

      <section className="why-section">
        <div className="section-kicker">
          INTELLIGENCE YOU CAN DEFEND
        </div>

        <h2>
          One message.
          <br />
          <em>Every</em> connection.
        </h2>

        <div className="feature-grid capability-grid">
          <article>
            <div className="capability-icon">◈</div>
            <h3>Explainable risk</h3>

            <div className="capability-lines">
              <span>Content</span>
              <span>Authentication</span>
              <span>URL</span>
              <span>Infrastructure</span>
            </div>

            <a href="#upload">View evidence →</a>
          </article>

          <article>
            <div className="capability-icon">⌁</div>
            <h3>Forensic relay trace</h3>

            <p>
              Map received hops and distinguish the trusted boundary
              from claimed routing data.
            </p>

            <a href="#upload">Trace route →</a>
          </article>

          <article>
            <div className="capability-icon">◎</div>
            <h3>Campaign intelligence</h3>

            <p>
              Connect investigations only when the analysis finds
              shared infrastructure.
            </p>

            <a href="#upload">Explore connections →</a>
          </article>
        </div>
      </section>
    </main>
  );
}

function Analyzing({ fileName }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const id = setInterval(
      () =>
        setStep((value) =>
          value < analysisSteps.length - 1
            ? value + 1
            : value
        ),
      420
    );

    return () => clearInterval(id);
  }, []);

  return (
    <main className="analysis-screen">
      <NetworkBackdrop />

      <div className="analysis-card">
        <div className="analysis-radar">
          <span />
          <span />
          <span />
          <b>⌁</b>
        </div>

        <div className="eyebrow">
          <span /> INVESTIGATION IN PROGRESS
        </div>

        <h1>Reading the signals.</h1>

        <p className="analysis-file">{fileName}</p>

        <ol>
          {analysisSteps.map((item, index) => (
            <li
              className={
                index < step
                  ? "done"
                  : index === step
                  ? "current"
                  : ""
              }
              key={item}
            >
              <span>
                {index < step
                  ? "✓"
                  : index === step
                  ? "◌"
                  : "·"}
              </span>

              {item}

              <small>
                {index < step
                  ? "complete"
                  : index === step
                  ? "running"
                  : "queued"}
              </small>
            </li>
          ))}
        </ol>
      </div>
    </main>
  );
}

function History({ openReport, newInvestigation, onAuthRequired }) {
  const [items, setItems] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  // No userId dependency anymore -- getHistory() reads whoever the
  // session cookie says is logged in, server-side. Each signed-in
  // user only ever sees their own rows.
  useEffect(() => {
    let active = true;

    getHistory()
      .then((data) => {
        if (active) {
          setItems(data.emails || []);
        }
      })
      .catch((err) => {
        if (!active) return;
        if (err.status === 401) { onAuthRequired(); return; }
        setError(err.message);
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  return (
    <main className="workspace-page">
      <div className="workspace-heading">
        <div>
          <div className="eyebrow">
            <span /> INVESTIGATION ARCHIVE
          </div>

          <h1>Recent investigations</h1>

          <p>
            Review historic email decisions and their connected
            infrastructure.
          </p>
        </div>

        <button
          className="analyze-button"
          onClick={newInvestigation}
        >
          + New investigation
        </button>
      </div>

      <div className="archive-list">
        {loading && <p>Loading investigations…</p>}

        {error && (
          <p className="upload-error">
            {error}
          </p>
        )}

        {!loading &&
          !error &&
          !items.length && (
            <p>
              No investigations have been created for this
              workspace yet.
            </p>
          )}

        {items.map((item) => (
          <button
            className="archive-row"
            key={item.email_id}
            onClick={() => openReport(item.email_id)}
          >
            <span
              className={`risk-pill ${String(
                item.verdict || "safe"
              ).toLowerCase()}`}
            >
              {item.verdict || "safe"}
            </span>

            <strong>
              {item.subject || item.email_id}
            </strong>

            <span className="archive-time">
              {item.ingested_at || "Date unavailable"}
            </span>

            <span className="archive-score">
              {item.overall_risk_score ?? "—"}
              <small>/100</small>
            </span>

            <span>→</span>
          </button>
        ))}
      </div>
    </main>
  );
}

function Settings() {
  const [provider, setProvider] = useState("Gmail");

  return (
    <main className="workspace-page email-test-page">
      <form
        className="email-test-card"
        aria-labelledby="email-test-title"
        onSubmit={(event) => event.preventDefault()}
      >
        <Mark />

        <div>
          <div className="eyebrow">
            <span /> SECURE WORKSPACE
          </div>

          <h1 id="email-test-title">
            Sign in to MailSentinel
          </h1>
        </div>

        <div
          className="provider-list"
          role="radiogroup"
          aria-label="Email provider"
        >
          {["Gmail", "Rediffmail", "Yahoo Mail"].map(
            (name) => (
              <label
                className="provider-option"
                key={name}
              >
                <input
                  type="radio"
                  name="provider"
                  value={name}
                  checked={provider === name}
                  onChange={() => setProvider(name)}
                />

                {name}
              </label>
            )
          )}
        </div>

        <label className="email-field">
          Email address

          <input
            type="email"
            placeholder="you@example.com"
            required
          />
        </label>

        <button
          className="analyze-button"
          type="submit"
        >
          Login / Continue
        </button>
      </form>
    </main>
  );
}

export default function App() {
  const [theme, setTheme] = useState("dark");
  const [view, setView] = useState("landing");
  const [fileName, setFileName] = useState("");
  const [user, setUser] = useState(null);
  const [investigationData, setInvestigationData] =
    useState(null);
  const [analysisError, setAnalysisError] = useState("");

  // Who's signed in, per the session cookie -- fetched once on load
  // and re-fetched after returning from Google OAuth or an add-in's
  // magic link (both land back here with the cookie already set).
  const refreshUser = () => {
    getCurrentUser()
      .then((data) => setUser(data.authenticated && data.user ? data.user : null))
      .catch(() => setUser(null));
  };
  useEffect(() => { refreshUser(); }, []);
  useEffect(() => {
    if (view === "login" && user) refreshUser();
  }, [view]);

  useEffect(() => {
    document.documentElement.setAttribute(
      "data-theme",
      theme
    );
  }, [theme]);

  const home = () => {
    setInvestigationData(null);
    setView("landing");
  };

  useEffect(() => {
    const params = new URLSearchParams(
      window.location.search
    );

    const investigationId =
      params.get("investigation");

    if (!investigationId) return;

    (async () => {
      setInvestigationData(null);
      setView("analyzing");
      setFileName(investigationId);

      try {
        const result =
          await getInvestigation(investigationId);

        setInvestigationData(result);
        setView("report");
      } catch (err) {
        console.error(
          "Failed to load investigation:",
          err
        );

        setView(err.status === 401 ? "login" : "landing");
      }
    })();
  }, []);

  const start = async (file) => {
    if (!user) { setView("login"); return; }

    setAnalysisError("");
    setInvestigationData(null);

    setFileName(
      file?.name || "sample-phishing-email.eml"
    );

    setView("analyzing");

    try {
      // No user_id here -- the backend reads it from the session, so
      // this always lands against whoever is actually logged in.
      const body = file
        ? { raw_eml: await file.text() }
        : { eml_path: "test_emails/example.eml" };

      const result = await analyzeEmail(body);

      setInvestigationData(result);
      setView("report");
    } catch (err) {
      console.error("Analysis failed:", err);

      if (err.status === 401) { setView("login"); return; }

      setAnalysisError(
        err.message ||
          "Unable to reach the analysis service. Check that the backend is running."
      );

      setInvestigationData(null);
      setView("landing");
    }
  };

  const goHistory = () => setView(user ? "history" : "login");

  return (
    <div className="app-shell">
      <Topbar
        theme={theme}
        setTheme={setTheme}
        onHome={home}
        view={view}
        setView={(v) => (v === "history" ? goHistory() : setView(v))}
        user={user}
      />

      {view === "login" && <LoginPage />}

      {view === "landing" && (
        <Landing
          onAnalyze={start}
          analysisError={analysisError}
        />
      )}

      {view === "analyzing" && (
        <Analyzing fileName={fileName} />
      )}

      {view === "report" && (
        <InvestigationReportPage
          apiResponse={investigationData}
          onNewInvestigation={home}
        />
      )}

      {view === "history" && (
        <History
          openReport={async (id) => {
            try {
              setInvestigationData(
                await getInvestigation(id)
              );

              setView("report");
            } catch (err) {
              if (err.status === 401) { setView("login"); return; }
              setAnalysisError(err.message);
              setView("landing");
            }
          }}
          newInvestigation={home}
          onAuthRequired={() => setView("login")}
        />
      )}

      {view === "settings" && <Settings />}
    </div>
  );
}