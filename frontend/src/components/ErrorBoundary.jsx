import { Component } from "react";

// The app had no error boundary anywhere, so any uncaught render
// crash (three different ones were found and fixed in one session --
// a backend-sent object rendered where a string was expected, in
// InvestigationReportPage.jsx and twice in CampaignGraph.jsx) took
// down the ENTIRE page to a blank white screen with zero indication
// of what happened. A backend that's still actively changing response
// shapes (new SVM classifier fields, campaign-graph node formats) will
// likely produce more of these before everyone's finished wiring it
// up. This doesn't fix the underlying shape mismatches -- it just
// makes the next one show a recoverable message instead of nothing.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Goes to the browser console (F12 -> Console), same place the
    // "Minified React error #31" messages were read from to find the
    // last three bugs -- keep using it the same way for any new one.
    console.error("MailSentinel crashed while rendering:", error, info);
  }

  handleReset = () => {
    this.setState({ error: null });
    if (this.props.onReset) this.props.onReset();
  };

  render() {
    if (this.state.error) {
      return (
        <main className="report">
          <div className="empty-state" style={{ maxWidth: 560, margin: "64px auto", textAlign: "center" }}>
            <p style={{ fontSize: 18, marginBottom: 8 }}>
              Something went wrong displaying this page.
            </p>
            <p style={{ opacity: 0.7, marginBottom: 16 }}>
              {String(this.state.error?.message || this.state.error)}
            </p>
            <button className="analyze-button" onClick={this.handleReset}>
              Back to home
            </button>
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}