import { baseUrl } from "../utils/api";

export default function LoginPage() {
  const loginWithGoogle = () => {
    // Full page navigation (not fetch) -- this has to leave the SPA
    // so Google's own login screen can take over, then redirect back
    // to FRONTEND_URL once the backend sets the session cookie.
    window.location.href = `${baseUrl}/auth/google`;
  };

  return (
    <main className="workspace-page email-test-page">
      <div className="email-test-card">
        <img
          className="login-brand-logo"
          src="/mail-sentinel-mark.png"
          alt=""
          aria-hidden="true"
        />

        <div className="eyebrow">
          <span /> SECURE WORKSPACE
        </div>

        <h1>Sign in to MailSentinel</h1>

        <p>Choose your email provider to continue.</p>

        <div className="provider-list">
          <button
            type="button"
            className="provider-option"
            onClick={loginWithGoogle}
          >
            Continue with Gmail
          </button>

          <button type="button" className="provider-option" disabled>
            Continue with Yahoo
          </button>

          <button type="button" className="provider-option" disabled>
            Continue with Rediffmail
          </button>
        </div>
      </div>
    </main>
  );
}
