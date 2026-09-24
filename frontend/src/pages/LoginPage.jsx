export default function LoginPage() {
  const loginWithGoogle = () => {
    window.location.href = "http://127.0.0.1:5001/auth/google";
  };

  return (
    <main className="workspace-page email-test-page">
      <div className="email-test-card">
        <div className="brand-mark">⌁</div>

        <div className="eyebrow">
          <span /> SECURE WORKSPACE
        </div>

        <h1>Sign in to MailSentinel</h1>

        <p>
          Choose your email provider to continue.
        </p>

        <div className="provider-list">
          <button
            type="button"
            className="provider-option"
            onClick={loginWithGoogle}
          >
            Continue with Gmail
          </button>

          <button
            type="button"
            className="provider-option"
            disabled
          >
            Continue with Yahoo
          </button>

          <button
            type="button"
            className="provider-option"
            disabled
          >
            Continue with Rediffmail
          </button>
        </div>
      </div>
    </main>
  );
}