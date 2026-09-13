function analyzeCurrentEmail(e) {
  var messageId = e && e.gmail && e.gmail.messageId;
  var accessToken = e && e.gmail && e.gmail.accessToken;

  if (!messageId) {
    return buildErrorCard('Open an email and try again.');
  }

  if (!accessToken) {
    return buildErrorCard('Gmail did not provide current-message access.');
  }

  try {
    // Authorize access to the currently opened Gmail message.
    GmailApp.setCurrentMessageAccessToken(accessToken);

    var message = GmailApp.getMessageById(messageId);

    var response = UrlFetchApp.fetch(getApiUrl() + '/analyze', {
      method: 'post',
      contentType: 'application/json',
      headers: {
        'X-API-Key': getApiKey()
      },
      payload: JSON.stringify({
        raw_eml: message.getRawContent(),
        user_id: Session.getActiveUser().getEmail()
      }),
      muteHttpExceptions: true
    });

    var result = JSON.parse(response.getContentText() || '{}');

    if (response.getResponseCode() < 200 ||
        response.getResponseCode() >= 300) {
      return buildErrorCard(
        result.error || 'MailSentinel API error.'
      );
    }

    return buildResultCard(result);

  } catch (err) {
    return buildErrorCard(
      'Unable to analyze: ' + err.message
    );
  }
}

function getApiUrl() {
  var url = PropertiesService.getScriptProperties().getProperty('MAILSENTINEL_API_URL');
  if (!url) throw new Error('Set MAILSENTINEL_API_URL in Script properties.');
  return url.replace(/\/$/, '');
}

function getApiKey() {
  var key = PropertiesService
    .getScriptProperties()
    .getProperty('MAILSENTINEL_API_KEY');

  if (!key) {
    throw new Error(
      'Set MAILSENTINEL_API_KEY in Script properties.'
    );
  }

  return key;
}

function getWebsiteUrl() {
  var url = PropertiesService.getScriptProperties().getProperty('MAILSENTINEL_WEBSITE_URL');
  if (!url) throw new Error('Set MAILSENTINEL_WEBSITE_URL in Script properties.');
  return url.replace(/\/$/, '');
}

function buildResultCard(r) {
  var a = r.header_auth || {};
  var d = (r.domains || []).slice(0, 5).map(function(x) { return '<b>' + escapeHtml(x.domain || 'Unknown') + '</b>: ' + (x.risk_level || 'unknown') + ' (' + (x.risk_score == null ? 'N/A' : x.risk_score) + ')'; }).join('<br>') || 'No domains found.';

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MAILSENTINEL').setSubtitle('Analysis complete'))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText('<b>Verdict:</b> ' + escapeHtml(r.verdict || 'Unknown') + '<br><b>Risk score:</b> ' + (r.overall_risk_score == null ? 'N/A' : r.overall_risk_score) + '<br><b>Subject:</b> ' + escapeHtml(r.subject || '(no subject)'))))
    .addSection(CardService.newCardSection().setHeader('Authentication').addWidget(CardService.newTextParagraph().setText('SPF: ' + (a.spf || 'N/A') + '<br>DMARC: ' + (a.dmarc || 'N/A'))))
    .addSection(CardService.newCardSection().setHeader('Domains').addWidget(CardService.newTextParagraph().setText(d)))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextButton()
        .setText('VIEW FULL INVESTIGATION')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOpenLink(CardService.newOpenLink().setUrl(getWebsiteUrl() + '?investigation=' + encodeURIComponent(r.email_id)))
    ))
    .build();
}

function buildErrorCard(message) {
  return CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle('MAILSENTINEL').setSubtitle('Error')).addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText('<b>Error:</b> ' + escapeHtml(message)))).build();
}

function escapeHtml(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}