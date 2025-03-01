// content-email.js
class EmailAnalyzer {
    constructor() {
        this.websocket = null;
        this.setupWebSocket();
        this.setupObserver();
    }

    setupWebSocket() {
        this.websocket = new WebSocket('wss://phishing-detection-system-jig1.onrender.com/ws');
        
        this.websocket.onopen = () => {
            console.log('WebSocket connected');
        };

        this.websocket.onmessage = (event) => {
            const result = JSON.parse(event.data);
            this.showAnalysisResult(result);
        };

        this.websocket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    setupObserver() {
        // Create observer to detect when email content is loaded
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (this.isEmailView(mutation.target)) {
                    this.analyzeEmail(mutation.target);
                }
            });
        });

        // Start observing
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    isEmailView(element) {
        // Customize this based on email provider's DOM structure
        if (window.location.hostname.includes('gmail')) {
            return element.matches('.adn.ads'); // Gmail email content class
        }
        // Add conditions for other email providers
        return false;
    }

    async analyzeEmail(emailElement) {
        try {
            const emailData = this.extractEmailData(emailElement);
            
            // Send to WebSocket for analysis
            this.websocket.send(JSON.stringify({
                type: 'analyze_email',
                data: emailData
            }));
        } catch (error) {
            console.error('Error analyzing email:', error);
        }
    }

    extractEmailData(emailElement) {
        // Extract email data based on provider
        if (window.location.hostname.includes('gmail')) {
            return {
                subject: this.getGmailSubject(),
                sender: this.getGmailSender(),
                body: emailElement.innerText,
                html: emailElement.innerHTML,
                links: this.extractLinks(emailElement)
            };
        }
        // Add extractors for other email providers
        return null;
    }

    getGmailSubject() {
        const subjectElement = document.querySelector('.hP');
        return subjectElement ? subjectElement.innerText : '';
    }

    getGmailSender() {
        const senderElement = document.querySelector('.gD');
        return senderElement ? senderElement.getAttribute('email') : '';
    }

    extractLinks(element) {
        const links = element.getElementsByTagName('a');
        return Array.from(links).map(link => ({
            text: link.innerText,
            href: link.href
        }));
    }

    showAnalysisResult(result) {
        // Create and show modal with analysis results
        const modal = this.createModal(result);
        document.body.appendChild(modal);
    }

    createModal(result) {
        const modal = document.createElement('div');
        modal.className = 'email-analysis-modal';
        
        const verdict = result.is_phishing ? 'Potential Phishing' : 'Likely Safe';
        const verdictClass = result.is_phishing ? 'phishing' : 'safe';

        modal.innerHTML = `
            <div class="modal-content ${verdictClass}">
                <span class="close-button">&times;</span>
                <h2>Email Analysis Result</h2>
                <div class="verdict ${verdictClass}">
                    <h3>${verdict}</h3>
                    <div class="confidence-meter">
                        <div class="meter-fill" style="width: ${result.confidence * 100}%"></div>
                    </div>
                    <span class="confidence-text">Confidence: ${(result.confidence * 100).toFixed(1)}%</span>
                </div>
                
                <div class="analysis-details">
                    <h3>Key Findings</h3>
                    <ul>
                        ${this.generateFindings(result)}
                    </ul>
                </div>

                <div class="recommendations">
                    <h3>Recommendations</h3>
                    <ul>
                        ${this.generateRecommendations(result)}
                    </ul>
                </div>
            </div>
        `;

        // Add event listeners
        const closeButton = modal.querySelector('.close-button');
        closeButton.onclick = () => modal.remove();

        return modal;
    }

    generateFindings(result) {
        const findings = [];
        const features = result.features;

        if (features.suspicious_url_count > 0) {
            findings.push(`Contains ${features.suspicious_url_count} suspicious URLs`);
        }
        if (features.contains_urgent) {
            findings.push('Contains urgent or time-sensitive language');
        }
        if (features.contains_personal) {
            findings.push('Requests for personal information detected');
        }
        // Add more findings based on features

        return findings.map(finding => `<li>${finding}</li>`).join('');
    }

    generateRecommendations(result) {
        const recommendations = [];
        
        if (result.is_phishing) {
            recommendations.push(
                'Do not click on any links in this email',
                'Do not download any attachments',
                'Do not reply with personal information',
                'Report this email as phishing'
            );
        } else {
            recommendations.push(
                'Email appears safe but always remain cautious',
                'Verify sender identity if unsure',
                'Never provide sensitive information unless absolutely necessary'
            );
        }

        return recommendations.map(rec => `<li>${rec}</li>`).join('');
    }
}

// Initialize the analyzer
new EmailAnalyzer();