function buildHomeCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("MAILSENTINEL")
        .setSubtitle("Email Security Analysis")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("Open an email and analyze it with MailSentinel.")
        )
    )
    .build();
}

function buildAnalyzeCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("MAILSENTINEL")
        .setSubtitle("Email Security Analysis")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("<b>Ready to analyze this email</b>")
        )
        .addWidget(
          CardService.newTextButton()
            .setText("ANALYZE THIS EMAIL")
            .setTextButtonStyle(
              CardService.TextButtonStyle.FILLED
            )
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName("analyzeCurrentEmail")
            )
        )
    )
    .build();
}