
/*
 * MailSentinel Outlook Add-in
 *
 * Reads the currently opened Outlook email and sends it
 * to the MailSentinel analysis backend.
 */

// ======================================================
// CONFIGURATION
// ======================================================

// Use your deployed backend URL here.
// Do not use localhost for an Outlook add-in running
// outside your own computer.
//
// Example: https://your-backend-domain.com
const API_BASE_URL = "YOUR_BACKEND_URL";

// Use the same API key configured on your Flask backend.
// Do not commit a real key to GitHub.
const API_KEY = "YOUR_API_KEY";


// ======================================================
// INITIALIZATION
// ======================================================

Office.onReady(function (info) {
    if (info.host === Office.HostType.Outlook) {
        initializeAddin();
    }
});

function initializeAddin() {
    const analyzeBtn = document.getElementById("analyzeBtn");
    const resetBtn = document.getElementById("resetBtn");

    analyzeBtn.addEventListener("click", analyzeCurrentEmail);
    resetBtn.addEventListener("click", resetResults);

    loadCurrentEmailInfo();

    document.getElementById("connectionDot")
        .classList.add("connected");
}


// ======================================================
// CURRENT EMAIL
// ======================================================

function loadCurrentEmailInfo() {
    const item = Office.context.mailbox.item;

    if (!item) {
        document.getElementById("emailSubject").textContent =
            "No email selected";

        document.getElementById("emailSender").textContent =
            "Open an email in Outlook";

        return;
    }

    document.getElementById("emailSubject").textContent =
        item.subject || "No subject";

    let sender = "Unknown sender";

    if (item.from && item.from.emailAddress) {
        sender = item.from.emailAddress;
    }

    document.getElementById("emailSender").textContent = sender;

    document.getElementById("emailStatus").textContent =
        "Ready to analyze";
}


// ======================================================
// ANALYZE EMAIL
// ======================================================

async function analyzeCurrentEmail() {
    const item = Office.context.mailbox.item;

    if (!item) {
        showError("Please open an email in Outlook first.");
        return;
    }

    if (
        !API_BASE_URL ||
        API_BASE_URL === "YOUR_BACKEND_URL" ||
        !API_KEY ||
        API_KEY === "YOUR_API_KEY"
    ) {
        showError(
            "The backend configuration is missing. " +
            "Configure the API URL and API key in taskpane.js."
        );
        return;
    }

    setLoading(true);
    hideError();
    document.getElementById("resultsSection").classList.add("hidden");

    try {
        const rawEmail = await getRawEmail(item);

        if (!rawEmail) {
            throw new Error(
                "Could not retrieve the email content from Outlook."
            );
        }

        const response = await fetch(
            API_BASE_URL.replace(/\/+$/, "") + "/analyze",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json",
                    "X-API-Key": API_KEY
                },

                body: JSON.stringify({
                    raw_eml: rawEmail
                })
            }
        );

        const responseText = await response.text();

        let data;

        try {
            data = JSON.parse(responseText);
        } catch {
            throw new Error(
                "The backend returned an invalid response."
            );
        }

        if (!response.ok) {
            throw new Error(
                data.error ||
                data.message ||
                "Backend error: " + response.status
            );
        }

        displayResults(data);

        document.getElementById("emailStatus").textContent =
            "Analysis completed";

    } catch (error) {
        console.error("MailSentinel analysis error:", error);

        showError(
            error.message ||
            "Unable to analyze the email. Please try again."
        );

        document.getElementById("emailStatus").textContent =
            "Analysis failed";

    } finally {
        setLoading(false);
    }
}


// ======================================================
// GET EMAIL CONTENT
// ======================================================

function getRawEmail(item) {
    return new Promise(function (resolve, reject) {

        /*
         * Outlook JavaScript APIs differ by Outlook version.
         *
         * This first implementation retrieves the selected
         * message's body and metadata. The backend should
         * receive the raw .eml format when available.
         *
         * Body retrieval is supported through Office.js.
         */

        item.body.getAsync(
            Office.CoercionType.Text,
            function (result) {

                if (result.status !== Office.AsyncResultStatus.Succeeded) {
                    reject(
                        new Error(
                            "Unable to read the email body. " +
                            "Check Outlook permissions."
                        )
                    );
                    return;
                }

                const body = result.value || "";

                const subject = item.subject || "";

                const sender =
                    item.from && item.from.emailAddress
                        ? item.from.emailAddress
                        : "unknown";

                const recipient =
                    item.to
                        ? item.to.map(function (person) {
                            return person.emailAddress;
                        }).join(", ")
                        : "";

                const date =
                    item.dateTimeCreated
                        ? new Date(item.dateTimeCreated).toUTCString()
                        : new Date().toUTCString();

                /*
                 * This is a basic RFC-822-style message
                 * representation, NOT the original raw .eml.
                 *
                 * It is sufficient for a first content-analysis
                 * integration but will not preserve the original
                 * Received headers or authentication results.
                 */

                const message =
                    "From: " + sender + "\r\n" +
                    "To: " + recipient + "\r\n" +
                    "Subject: " + subject + "\r\n" +
                    "Date: " + date + "\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    body;

                resolve(message);
            }
        );
    });
}


// ======================================================
// DISPLAY RESULTS
// ======================================================

function displayResults(data) {
    document.getElementById("resultsSection")
        .classList.remove("hidden");

    /*
     * The backend's response schema may use different names.
     * These helpers support the common MailSentinel field names
     * and a few common alternatives.
     */

    const risk = getNumber(
        data.overall_risk_score,
        data.risk_score,
        data.final_risk_score,
        data.phishing_score
    );

    const verdict = getString(
        data.verdict,
        data.final_verdict,
        data.risk_level
    ) || "Unknown";

    const normalizedVerdict = verdict.toLowerCase();

    document.getElementById("riskScore").textContent =
        risk === null ? "--" : Math.round(risk);

    document.getElementById("verdictBadge").textContent =
        verdict.toUpperCase();

    const badge = document.getElementById("verdictBadge");
    badge.className = "verdict-badge";

    if (
        normalizedVerdict.includes("high") ||
        normalizedVerdict.includes("phishing")
    ) {
        badge.classList.add("high");
    } else if (
        normalizedVerdict.includes("medium") ||
        normalizedVerdict.includes("suspicious")
    ) {
        badge.classList.add("medium");
    } else if (
        normalizedVerdict.includes("low") ||
        normalizedVerdict.includes("safe") ||
        normalizedVerdict.includes("legitimate")
    ) {
        badge.classList.add("low");
    }

    document.getElementById("riskDescription").textContent =
        getString(
            data.summary,
            data.explanation,
            data.reason
        ) || "See the security findings below.";

    const classifier = data.classifier || data.content_analysis || {};

    const contentScore = getNumber(
        classifier.phishing_score,
        classifier.risk_score,
        data.phishing_score
    );

    document.getElementById("contentScore").textContent =
        contentScore === null
            ? "--"
            : Math.round(contentScore * 100) + "%";

    const auth = data.authentication || data.auth_results || {};

    document.getElementById("spfResult").textContent =
        getString(auth.spf, data.spf_result) || "Not available";

    document.getElementById("dkimResult").textContent =
        getString(auth.dkim, data.dkim_result) || "Not available";

    document.getElementById("dmarcResult").textContent =
        getString(auth.dmarc, data.dmarc_result) || "Not available";

    updateAuthClass("spfResult");
    updateAuthClass("dkimResult");
    updateAuthClass("dmarcResult");

    const infrastructure =
        data.infrastructure ||
        data.infrastructure_analysis ||
        {};

    document.getElementById("infraStatus").textContent =
        getString(
            infrastructure.verdict,
            infrastructure.risk_level,
            infrastructure.status
        ) || "Analyzed";

    const correlation =
        data.correlation ||
        data.campaign_intelligence ||
        {};

    document.getElementById("correlationStatus").textContent =
        getString(
            correlation.related_count,
            correlation.related_investigations,
            correlation.status
        ) || "Available";

    displayFindings(data);
}


// ======================================================
// FINDINGS
// ======================================================

function displayFindings(data) {
    const container = document.getElementById("findingsList");

    container.innerHTML = "";

    let findings = [];

    if (Array.isArray(data.findings)) {
        findings = data.findings;
    } else if (Array.isArray(data.security_findings)) {
        findings = data.security_findings;
    } else if (Array.isArray(data.reasons)) {
        findings = data.reasons;
    }

    if (findings.length === 0) {
        const item = document.createElement("div");
        item.className = "finding-item";
        item.textContent =
            "No detailed findings were returned by the backend.";

        container.appendChild(item);
        return;
    }

    findings.forEach(function (finding) {
        const row = document.createElement("div");
        row.className = "finding-item";

        const marker = document.createElement("span");
        marker.className = "finding-marker";
        marker.textContent = "◆";

        const text = document.createElement("span");

        if (typeof finding === "string") {
            text.textContent = finding;
        } else {
            text.textContent =
                finding.description ||
                finding.message ||
                finding.reason ||
                JSON.stringify(finding);
        }

        row.appendChild(marker);
        row.appendChild(text);

        container.appendChild(row);
    });
}


// ======================================================
// HELPERS
// ======================================================

function getNumber() {
    for (let i = 0; i < arguments.length; i++) {
        const value = arguments[i];

        if (value !== undefined && value !== null && value !== "") {
            const number = Number(value);

            if (Number.isFinite(number)) {
                return number;
            }
        }
    }

    return null;
}

function getString() {
    for (let i = 0; i < arguments.length; i++) {
        const value = arguments[i];

        if (value !== undefined && value !== null && value !== "") {
            return String(value);
        }
    }

    return null;
}

function updateAuthClass(elementId) {
    const element = document.getElementById(elementId);
    const value = element.textContent.toLowerCase();

    element.className = "auth-value";

    if (value.includes("pass")) {
        element.classList.add("pass");
    } else if (value.includes("fail")) {
        element.classList.add("fail");
    } else {
        element.classList.add("neutral");
    }
}

function setLoading(loading) {
    const button = document.getElementById("analyzeBtn");
    const text = document.getElementById("buttonText");

    button.disabled = loading;

    text.textContent = loading
        ? "Analyzing email..."
        : "Analyze This Email";
}

function showError(message) {
    const errorBox = document.getElementById("errorBox");

    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}

function hideError() {
    document.getElementById("errorBox")
        .classList.add("hidden");
}

function resetResults() {
    document.getElementById("resultsSection")
        .classList.add("hidden");

    document.getElementById("emailStatus").textContent =
        "Ready to analyze";

    hideError();
    loadCurrentEmailInfo();
}