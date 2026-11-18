import React, { useState } from 'react';

const QUIZ_QUESTIONS = [
  {
    id: 1,
    question: "You receive an urgent email claiming your bank account is suspended and providing a link 'http://secure-update.chase-login.xyz/verify'. What is the most obvious red flag?",
    options: [
      "The URL uses a '.xyz' Top-Level Domain and unusual subdomain masking instead of the official bank domain",
      "The email contains text in English",
      "The link starts with http:// instead of ftp://",
      "The word 'verify' is spelled correctly"
    ],
    correctAnswer: 0,
    explanation: "Legitimate financial institutions always use their official registered domains (e.g., chase.com) and valid TLS certificates. Abused TLDs such as .xyz, .top, or .cam combined with urgency are classic phishing indicators."
  },
  {
    id: 2,
    question: "A link is formatted as 'http://paypal.com@attacker-controlled-server.com/login'. Where does clicking this link actually take your browser?",
    options: [
      "To PayPal's official portal",
      "To attacker-controlled-server.com because the '@' symbol treats preceding characters as username credentials",
      "It will trigger an automatic browser crash",
      "To your local router homepage"
    ],
    correctAnswer: 1,
    explanation: "In standard URI syntax (RFC 3986), characters before an '@' symbol are parsed as authentication credentials. Attackers leverage this trick to deceive victims into thinking they are navigating to the trusted brand domain."
  },
  {
    id: 3,
    question: "What is 'Quishing' (QR Phishing) and how does it compromise users?",
    options: [
      "A technique that sends phishing messages exclusively through Bluetooth",
      "Malicious QR codes placed in emails or public stickers that encode deceptive URLs, bypassing traditional email text scanners",
      "Scanning a QR code that directly drains your laptop battery",
      "Encrypting your QR code using blockchain"
    ],
    correctAnswer: 1,
    explanation: "Quishing hides malicious URLs within a 2D QR barcode image. Traditional text-based email security filters often fail to parse the embedded URL, tricking users into scanning it with their mobile devices."
  },
  {
    id: 4,
    question: "You notice a login link with the domain 'goog1e.com' or 'paypaI.com' (with a capital 'I' replacing 'l'). What attack technique is this?",
    options: [
      "Buffer Overflow",
      "Cross-Site Scripting (XSS)",
      "Typosquatting / Homograph Brand Spoofing",
      "SQL Injection"
    ],
    correctAnswer: 2,
    explanation: "Typosquatting and homograph attacks register lookalike domain names with visual similarities (substituting letters with numbers or alternate Unicode glyphs) to mislead victims into entering sensitive passwords."
  },
  {
    id: 5,
    question: "Why should you never evaluate a suspected phishing URL by opening it directly in your primary web browser?",
    options: [
      "The site may execute drive-by browser exploit kits, malicious downloads, or log your public IP address and browser fingerprint",
      "It will delete your operating system immediately",
      "Internet service providers disconnect users for visiting any HTTP site",
      "It makes the computer run out of RAM instantly"
    ],
    correctAnswer: 0,
    explanation: "Visiting malicious sites can trigger drive-by malware downloads, zero-day browser exploits, or signal to threat actors that your email address is active. Always use headless, zero-execution heuristic analyzers like PhishGuard."
  }
];

export default function Awareness() {
  const [selectedAnswers, setSelectedAnswers] = useState({});
  const [submitted, setSubmitted] = useState(false);

  const handleSelect = (qId, optionIdx) => {
    if (submitted) return;
    setSelectedAnswers(prev => ({
      ...prev,
      [qId]: optionIdx
    }));
  };

  const calculateScore = () => {
    let score = 0;
    QUIZ_QUESTIONS.forEach(q => {
      if (selectedAnswers[q.id] === q.correctAnswer) {
        score++;
      }
    });
    return score;
  };

  const resetQuiz = () => {
    setSelectedAnswers({});
    setSubmitted(false);
  };

  const score = calculateScore();
  const allAnswered = QUIZ_QUESTIONS.every(q => selectedAnswers[q.id] !== undefined);

  return (
    <div className="awareness-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Interactive Phishing Awareness Academy</h1>
          <p className="page-subtitle">Test your defensive instincts against real-world social engineering and deceptive link techniques</p>
        </div>
      </div>

      {/* Quiz Card */}
      <div className="glass-panel">
        <div className="panel-header">
          <h3 className="panel-title">Cyber Hygiene & Phishing Indicator Assessment</h3>
          <span className="badge-pill">5 High-Impact Questions</span>
        </div>

        {submitted && (
          <div className={`quiz-score-banner ${score >= 4 ? 'banner-pass' : 'banner-review'}`}>
            <div className="score-summary">
              <h4>Assessment Score: {score} / {QUIZ_QUESTIONS.length} ({Math.round((score / QUIZ_QUESTIONS.length) * 100)}%)</h4>
              <p>
                {score === 5
                  ? "Outstanding! You possess advanced phishing detection instincts. You are well-defended against deceptive links."
                  : score >= 3
                  ? "Good job! You recognized key indicators. Review the explanations below to refine your threat hunting awareness."
                  : "Caution recommended! Review the detailed explanations below to understand how threat actors manipulate URL structures."}
              </p>
            </div>
            <button className="btn-secondary" onClick={resetQuiz}>Retake Quiz</button>
          </div>
        )}

        <div className="quiz-questions-list mt-4">
          {QUIZ_QUESTIONS.map((q, idx) => {
            const userAnswer = selectedAnswers[q.id];
            const isCorrect = userAnswer === q.correctAnswer;

            return (
              <div key={q.id} className="quiz-question-card">
                <div className="question-title">
                  <span className="q-number">Q{idx + 1}.</span> {q.question}
                </div>

                <div className="options-grid">
                  {q.options.map((opt, oIdx) => {
                    const isSelected = userAnswer === oIdx;
                    let optionClass = 'option-btn';
                    if (isSelected) optionClass += ' selected';
                    if (submitted) {
                      if (oIdx === q.correctAnswer) optionClass += ' correct-highlight';
                      else if (isSelected && !isCorrect) optionClass += ' wrong-highlight';
                    }

                    return (
                      <button
                        key={oIdx}
                        className={optionClass}
                        onClick={() => handleSelect(q.id, oIdx)}
                      >
                        <span className="opt-letter">{String.fromCharCode(65 + oIdx)}</span>
                        <span className="opt-text">{opt}</span>
                      </button>
                    );
                  })}
                </div>

                {submitted && (
                  <div className={`explanation-box ${isCorrect ? 'exp-correct' : 'exp-wrong'}`}>
                    <strong>{isCorrect ? '✓ Correct!' : '✕ Needs Review:'}</strong> {q.explanation}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {!submitted ? (
          <div className="panel-footer mt-6">
            <button
              className="btn-primary"
              disabled={!allAnswered}
              onClick={() => setSubmitted(true)}
            >
              Submit Answers ({Object.keys(selectedAnswers).length}/{QUIZ_QUESTIONS.length})
            </button>
          </div>
        ) : (
          <div className="panel-footer mt-6">
            <button className="btn-primary" onClick={resetQuiz}>
              Try Again
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
