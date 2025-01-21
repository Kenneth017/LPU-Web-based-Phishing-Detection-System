/**
 * Core Initialization and Configuration
 * script.new.js - Version 1.0
 */

// Global configuration
const CONFIG = {
    API_ENDPOINTS: {
        CHECK: '/check',
        ANALYSIS_DETAILS: '/analysis_details',
        REFRESH_ACTIVITY: '/refresh_activity',
        REANALYZE: '/reanalyze',
        EXPORT: '/export'
    },
    INPUT_PATTERNS: {
        hash: /^[a-fA-F0-9]{32,64}$/,
        ip: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/,
        url: /^(https?:\/\/|ftp:\/\/|www\.)/i,
        domain: /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/
    }
};

/**
 * Main initialization
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded');
    initializeCore();
});

function initializeCore() {
    const chartData = window.chartData;
    if (document.querySelector('.dashboard')) {
        initializeDashboardCharts(chartData?.trend_data, chartData?.distribution_data);
    }
    initializeInputDetection();
    initializeHistoryPage();
    initializeViewDetailsButtons();
    preventFormSubmitOnEnter();
    addEventListeners();
    lazyLoadImages();
}

/**
 * Input Detection and Handling
 */
function initializeInputDetection() {
    const inputField = document.getElementById('url-input');
    if (inputField) {
        inputField.addEventListener('input', e => updateInputTypeIndicator(e.target.value.trim()));
    }
}

function updateInputTypeIndicator(input) {
    const indicator = document.getElementById('input-type-indicator');
    if (!indicator) return;

    let inputType = Object.entries(CONFIG.INPUT_PATTERNS)
        .find(([, pattern]) => pattern.test(input))?.[0] || 'unknown';
    
    indicator.textContent = inputType.toUpperCase();
    indicator.className = `input-type-indicator ${inputType}`;
}

function preventFormSubmitOnEnter() {
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('keypress', e => {
            if (e.key === 'Enter') e.preventDefault();
        });
    }
}

/**
 * Form Validation
 */
function validateInput(input) {
    if (!input || typeof input !== 'string') return false;
    return input.trim() !== '';
}

/**
 * Loading State Management
 */
function setLoadingState(isLoading) {
    const loader = document.getElementById('loader');
    const result = document.getElementById('result');
    
    if (loader) loader.classList.toggle('hidden', !isLoading);
    if (result) result.classList.toggle('hidden', isLoading);
}

/**
 * Error Handling
 */
function handleError(error, context = '') {
    console.error(`Error in ${context}:`, error);
    
    const loader = document.getElementById('loader');
    const result = document.getElementById('result');
    const resultText = document.getElementById('result-text');

    if (loader) loader.classList.add('hidden');
    if (result) result.classList.remove('hidden');
    if (resultText) {
        resultText.textContent = 'An error occurred. Please try again.';
        resultText.className = 'error';
    }

    // Clear related elements
    ['community-score', 'metadata', 'vendor-analysis'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.innerHTML = '';
    });

    // Show user-friendly error message
    alert('An error occurred. Please try again.');
}

/**
 * Event Listeners
 */
function addEventListeners() {
    const analyzeButton = document.getElementById('analyze-button');
    if (analyzeButton) {
        analyzeButton.addEventListener('click', analyzeInput);
    }

    const refreshButton = document.querySelector('.btn-refresh');
    if (refreshButton) {
        refreshButton.addEventListener('click', refreshActivity);
    }

    // For dashboard export button
    const exportButton = document.querySelector('.btn-export');
    if (exportButton) {
        exportButton.addEventListener('click', () => {
            window.location.href = CONFIG.API_ENDPOINTS.EXPORT;
        });
    }
}

// Placeholder functions that will be defined in later sections
function initializeDashboardCharts() { console.log('Charts initialization pending...'); }
function initializeHistoryPage() { console.log('History page initialization pending...'); }
function initializeViewDetailsButtons() { console.log('View details buttons initialization pending...'); }
function analyzeInput() { console.log('Analyze input function pending...'); }
function refreshActivity() { console.log('Refresh activity function pending...'); }
function exportHistory() { console.log('Export history function pending...'); }
function lazyLoadImages() { console.log('Lazy load images function pending...'); }

/**
 * Chart Functionality
 */

function initializeDashboardCharts(trendData, distributionData) {
    console.log("Initializing charts with:", { trendData, distributionData });
    
    if (document.getElementById('detectionTrendsChart')) {
        initializeDetectionTrendsChart(trendData);
    } else {
        console.error("Detection Trends Chart container not found");
    }

    if (document.getElementById('distributionChart')) {
        initializeDistributionChart(distributionData);
    } else {
        console.error("Distribution Chart container not found");
    }
}

function initializeDetectionTrendsChart(trendData) {
    if (!trendData || !Array.isArray(trendData) || trendData.length === 0) {
        console.error('Invalid or empty trend data');
        return;
    }

    const options = {
        chart: {
            type: 'area',
            height: 350,
            background: 'transparent',
            toolbar: { show: false }
        },
        series: [
            {
                name: 'Safe URLs',
                data: trendData.map(day => day.safe_count || 0)
            },
            {
                name: 'Malicious URLs',
                data: trendData.map(day => (day.phishing_count || 0) + (day.malicious_count || 0) + (day.suspicious_count || 0))
            }
        ],
        colors: ['#50E3C2', '#FF4B4B'],
        fill: {
            type: 'gradient',
            gradient: {
                shadeIntensity: 1,
                opacityFrom: 0.7,
                opacityTo: 0.2,
                stops: [0, 90, 100]
            }
        },
        xaxis: {
            categories: trendData.map(day => day.check_date),
            labels: { style: { colors: '#CCCCCC' } }
        },
        yaxis: { labels: { style: { colors: '#CCCCCC' } } },
        tooltip: { theme: 'dark' }
    };

    new ApexCharts(document.getElementById("detectionTrendsChart"), options).render();
}

function initializeDistributionChart(distributionData) {
    if (!distributionData || typeof distributionData !== 'object') {
        console.error('Invalid distribution data');
        return;
    }

    const options = {
        chart: {
            type: 'donut',
            height: 350,
            background: 'transparent'
        },
        series: [
            distributionData.safe_count || 0,
            distributionData.phishing_count || 0,
            distributionData.suspicious_count || 0,
            distributionData.malicious_count || 0
        ],
        labels: ['Safe', 'Phishing', 'Suspicious', 'Malicious'],
        colors: ['#50E3C2', '#FF4B4B', '#FFA500', '#FF6347'],
        legend: { labels: { colors: '#CCCCCC' } },
        tooltip: { theme: 'dark' }
    };

    new ApexCharts(document.getElementById("distributionChart"), options).render();
}

function updateActivityTable(activities) {
    const tbody = document.querySelector('.activity-table tbody');
    if (!tbody || !activities) return;

    tbody.innerHTML = activities.map(activity => `
        <tr>
            <td class="url-cell"><div class="url-content">${activity.input_string}</div></td>
            <td><span class="status-badge ${activity.main_verdict}">${activity.main_verdict}</span></td>
            <td>${activity.analysis_date}</td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-icon" onclick="viewDetails('${activity.input_string}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-icon" onclick="reanalyze('${activity.input_string}')">
                        <i class="fas fa-redo"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

function animateCount(element, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        element.textContent = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

/**
 * Modal and Details Handling
 */

function initializeHistoryPage() {
    const modal = document.getElementById("detailModal");
    if (!modal) return;

    modal.style.display = "none";
    const closeButton = modal.querySelector('.close');
    if (closeButton) {
        closeButton.onclick = () => modal.style.display = "none";
    }
    window.onclick = (event) => {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    };
}

function initializeViewDetailsButtons() {
    const viewButtons = document.querySelectorAll('.view-details-btn');
    console.log('Found view buttons:', viewButtons.length);
    viewButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            const url = this.getAttribute('data-url');
            console.log('View details clicked for URL:', url);
            viewDetails(url);
        });
    });
}

async function viewDetails(url) {
    try {
        // Show modal with loader first
        showDetailsModal({ loading: true });

        const response = await fetch(`${CONFIG.API_ENDPOINTS.ANALYSIS_DETAILS}/${encodeURIComponent(url)}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const details = await response.json();
        
        // Show the actual content
        showDetailsModal(details);
        
    } catch (error) {
        console.error('Error fetching details:', error);
        
        // Show error in modal
        const modal = document.getElementById('detailModal');
        if (modal) {
            modal.innerHTML = `
                <div class="modal-content">
                    <span class="close">&times;</span>
                    <div class="modal-error">
                        <h3>Error Loading Details</h3>
                        <p>Failed to load analysis details. Please try again.</p>
                        <button onclick="modal.style.display='none'" class="btn btn-secondary">Close</button>
                    </div>
                </div>
            `;
        }
    }
}

function showDetailsModal(details) {
    // Create or get modal container
    let modal = document.getElementById('detailModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'detailModal';
        modal.className = 'modal modern-modal';
        document.body.appendChild(modal);
    }

    // Show loading state first
    modal.innerHTML = `
        <div class="modal-content">
            <span class="close">&times;</span>
            <div class="modal-loader">
                <div class="spinner"></div>
                <p>Loading analysis details...</p>
            </div>
        </div>
    `;
    modal.style.display = 'block';

    // Prepare the modal content
    const modalContent = `
        <div class="modal-content">
            <span class="close">&times;</span>
            <h2>Analysis Details</h2>
            
            <div class="details-section">
                <p><strong>URL:</strong> ${details.input_string || details.url || details.original_input || 'N/A'}</p>
                <p><strong>Analysis Date:</strong> ${details.analysis_date || 'N/A'}</p>
                <p><strong>Status:</strong> 
                    <span class="status-badge ${details.main_verdict?.toLowerCase() || 'unknown'}">
                        ${(details.main_verdict || 'Unknown').toUpperCase()}
                    </span>
                </p>
                <p><strong>Community Score:</strong> ${details.community_score || 'N/A'}</p>
            </div>

            ${details.metadata ? `
                <div class="metadata-section">
                    <h3>Additional Information</h3>
                    ${Object.entries(details.metadata)
                        .filter(([key, value]) => value !== null && value !== undefined)
                        .map(([key, value]) => `
                            <p><strong>${key.replace(/_/g, ' ').toUpperCase()}:</strong> ${value}</p>
                        `).join('')}
                </div>
            ` : ''}

            <div class="vendor-analysis">
                <h3>Vendor Analysis</h3>
                <table class="vendor-table">
                    <thead>
                        <tr>
                            <th>Vendor</th>
                            <th>Verdict</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${details.vendor_analysis
                            .sort((a, b) => a.name.localeCompare(b.name))
                            .map(vendor => `
                                <tr>
                                    <td>${vendor.name}</td>
                                    <td class="${vendor.verdict.toLowerCase()}">${vendor.verdict}</td>
                                </tr>
                            `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Set the content after a short delay
    setTimeout(() => {
        modal.innerHTML = modalContent;
    }, 300);

    // Show the modal after content is set
    requestAnimationFrame(() => {
        modal.style.display = 'block';
    });

    // Add event listeners
    const closeBtn = modal.querySelector('.close');
    closeBtn.onclick = () => {
        modal.style.display = 'none';
    };

    window.onclick = (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    };
}

function cleanupModal() {
    const modal = document.getElementById('detailModal');
    if (modal) {
        modal.remove();
    }
    window.onclick = null;
}

function displayResult(data) {
    updateResultText(data);
    updateCommunityScore(data);
    updateMetadata(data);
    updateVendorAnalysis(data);
}

function updateResultText(data) {
    const resultText = document.getElementById('result-text');
    if (!resultText) return;

    let finalVerdict = determineVerdict(data.vendor_analysis);
    resultText.textContent = `This input is ${finalVerdict === 'safe' ? 'safe' : 'potentially ' + finalVerdict}.`;
    resultText.className = finalVerdict;
}

function determineVerdict(vendorAnalysis) {
    if (!vendorAnalysis) return 'unknown';
    
    if (vendorAnalysis.some(v => v.verdict.toLowerCase() === 'phishing')) return 'phishing';
    if (vendorAnalysis.some(v => v.verdict.toLowerCase() === 'malicious')) return 'malicious';
    if (vendorAnalysis.some(v => v.verdict.toLowerCase() === 'suspicious')) return 'suspicious';
    return 'safe';
}

function updateCommunityScore(data) {
    const communityScore = document.getElementById('community-score');
    if (communityScore) {
        communityScore.textContent = `Community Score: ${data.community_score || 'N/A'}`;
    }
}

function updateMetadata(data) {
    if (!data.metadata) return;
    const finalUrl = document.getElementById('final-url');
    const servingIp = document.getElementById('serving-ip');
    if (finalUrl) finalUrl.textContent = `Final URL: ${data.metadata.final_url || 'N/A'}`;
    if (servingIp) servingIp.textContent = `Serving IP: ${data.metadata.serving_ip || 'N/A'}`;
}

function updateVendorAnalysis(data) {
    console.log('Updating vendor analysis with data:', data); // Debug log

    if (!data.vendor_analysis || !Array.isArray(data.vendor_analysis)) {
        console.error('Invalid vendor analysis data:', data.vendor_analysis);
        return;
    }

    const categories = ['phishing', 'malicious', 'suspicious', 'clean'];
    
    categories.forEach(category => {
        const container = document.getElementById(`${category}-vendors-container`);
        const table = document.getElementById(`${category}-vendors`);
        
        if (!container || !table) {
            console.error(`Container or table not found for ${category}`);
            return;
        }

        const filteredVendors = data.vendor_analysis.filter(vendor => {
            const verdict = vendor.verdict.toLowerCase();
            if (category === 'clean') {
                return ['clean', 'harmless', 'safe'].includes(verdict);
            }
            return verdict === category;
        });

        if (filteredVendors.length > 0) {
            container.style.display = 'block';
            const tbody = table.querySelector('tbody') || table.appendChild(document.createElement('tbody'));
            tbody.innerHTML = filteredVendors.map(vendor => `
                <tr>
                    <td>${vendor.name}</td>
                    <td class="${vendor.verdict.toLowerCase()}">${vendor.verdict}</td>
                </tr>
            `).join('');
        } else {
            container.style.display = 'none';
        }
    });
}

function updateVendorTable(containerId, tableId, vendors) {
    const container = document.getElementById(containerId);
    const table = document.getElementById(tableId);
    if (!container || !table) {
        console.error(`Container or table not found: ${containerId}, ${tableId}`);
        return;
    }

    if (vendors.length > 0) {
        container.style.display = 'block';
        let tbody = table.querySelector('tbody');
        if (!tbody) {
            tbody = document.createElement('tbody');
            table.appendChild(tbody);
        }
        tbody.innerHTML = vendors.map(vendor => `
            <tr>
                <td>${vendor.name}</td>
                <td class="${vendor.verdict.toLowerCase()}">${vendor.verdict}</td>
            </tr>
        `).join('');
    } else {
        container.style.display = 'none';
    }
}

/**
 * API Interactions and Data Handling
 */

async function analyzeInput() {
    const input = document.getElementById('url-input')?.value.trim();
    
    if (!validateInput(input)) {
        alert('Please enter a URL, domain, IP address, or file hash');
        return;
    }

    // Show loading indicator
    showLoadingIndicator();

    try {
        const response = await fetch(CONFIG.API_ENDPOINTS.CHECK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ input })
        });

        if (!response.ok) {
            throw new Error('Analysis failed');
        }

        const data = await response.json();
        
        if (data.status === 'success' && data.redirect) {
            // Redirect to the result page
            window.location.href = data.redirect;
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
    } catch (error) {
        hideLoadingIndicator();
        handleError(error, 'analyzeInput');
    }
}

function showLoadingIndicator() {
    // Hide the result table if it's visible
    const resultTable = document.getElementById('result');
    if (resultTable) {
        resultTable.style.display = 'none';
    }

    // Show a loading spinner or message
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'block';
    } else {
        // Create a loading indicator if it doesn't exist
        const indicatorHtml = `
            <div id="loading-indicator" class="loading-indicator">
                <div class="spinner"></div>
                <p>Analyzing... Please wait.</p>
            </div>
        `;
        document.querySelector('.container').insertAdjacentHTML('beforeend', indicatorHtml);
    }
}

function hideLoadingIndicator() {
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
}

async function refreshActivity() {
    try {
        const response = await fetch(CONFIG.API_ENDPOINTS.REFRESH_ACTIVITY);
        if (!response.ok) throw new Error('Failed to refresh activity');
        
        const data = await response.json();
        updateActivityTable(data.recent_activity);
    } catch (error) {
        handleError(error, 'refreshActivity');
    }
}

async function reanalyze(url) {
    if (!confirm('Are you sure you want to reanalyze this URL?')) return;

    try {
        const response = await fetch(CONFIG.API_ENDPOINTS.REANALYZE, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) throw new Error('Failed to reanalyze URL');
        
        const result = await response.json();
        alert('Analysis complete. The page will now reload.');
        location.reload();
    } catch (error) {
        handleError(error, 'reanalyze');
    }
}

function exportHistory() {
    // Check if we're on the dashboard page
    if (document.querySelector('.dashboard')) {
        // If on dashboard, use the existing export button
        const exportButton = document.querySelector('.btn-export');
        if (exportButton) {
            exportButton.click();
        } else {
            console.error('Export button not found on dashboard');
        }
    } else {
        // If not on dashboard, use the API endpoint directly
        window.location.href = CONFIG.API_ENDPOINTS.EXPORT;
    }
}

function safeJSONParse(str) {
    try {
        return JSON.parse(str);
    } catch (e) {
        console.error('JSON Parse Error:', e);
        return null;
    }
}

const DataFormatters = {
    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    },

    formatFileSize(bytes) {
        if (!bytes) return 'N/A';
        const units = ['B', 'KB', 'MB', 'GB'];
        let size = bytes;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        return `${size.toFixed(2)} ${units[unitIndex]}`;
    },

    formatDate(timestamp) {
        return timestamp ? new Date(timestamp * 1000).toLocaleDateString() : 'N/A';
    }
};

const DataValidators = {
    isValidUrl(url) {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    },

    isValidIP(ip) {
        return CONFIG.INPUT_PATTERNS.ip.test(ip);
    },

    isValidHash(hash) {
        return CONFIG.INPUT_PATTERNS.hash.test(hash);
    }
};

const DataTransformers = {
    groupVendorsByVerdict(vendors) {
        if (!Array.isArray(vendors)) return {};
        
        return vendors.reduce((acc, vendor) => {
            const verdict = vendor.verdict.toLowerCase();
            if (!acc[verdict]) acc[verdict] = [];
            acc[verdict].push(vendor);
            return acc;
        }, {});
    },

    extractMetadata(result) {
        if (!result || !result.metadata) return {};

        return {
            finalUrl: result.metadata.final_url || 'N/A',
            servingIp: result.metadata.serving_ip || 'N/A',
            // Add any other metadata fields you need
        };
    }
};

/**
 * Utility Functions and Helpers
 */

const UIHelpers = {
    /**
     * Debounce function to limit the rate at which a function can fire
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Throttle function to limit the rate at which a function can fire
     */
    throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        }
    },

    /**
     * Create and append a tooltip to an element
     */
    createTooltip(element, text) {
        const tooltip = document.createElement('div');
        tooltip.className = 'tooltip';
        tooltip.textContent = text;
        element.appendChild(tooltip);

        element.addEventListener('mouseover', () => tooltip.style.display = 'block');
        element.addEventListener('mouseout', () => tooltip.style.display = 'none');
    }
};

const DOMHelpers = {
    /**
     * Check if an element is in the viewport
     */
    isInViewport(element) {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    },

    /**
     * Lazy load images
     */
    lazyLoadImages() {
        const images = document.querySelectorAll('img[data-src]');
        images.forEach(img => {
            if (this.isInViewport(img)) {
                img.src = img.dataset.src;
                img.removeAttribute('data-src');
            }
        });
    },

    /**
     * Add event listener with automatic cleanup
     */
    addSafeEventListener(element, eventName, handler) {
        const wrappedHandler = (event) => {
            if (element.isConnected) {
                handler(event);
            } else {
                element.removeEventListener(eventName, wrappedHandler);
            }
        };
        element.addEventListener(eventName, wrappedHandler);
    },

    /**
     * Sanitize HTML string to prevent XSS
     */
    sanitizeHTML(html) {
        const temp = document.createElement('div');
        temp.textContent = html;
        return temp.innerHTML;
    }
};

const ColorHelpers = {
    /**
     * Get contrast color (black or white) based on background color
     */
    getContrastColor(hexcolor) {
        hexcolor = hexcolor.replace("#", "");
        const r = parseInt(hexcolor.substr(0,2),16);
        const g = parseInt(hexcolor.substr(2,2),16);
        const b = parseInt(hexcolor.substr(4,2),16);
        const yiq = ((r*299)+(g*587)+(b*114))/1000;
        return (yiq >= 128) ? 'black' : 'white';
    },

    /**
     * Generate a random color
     */
    getRandomColor() {
        return '#' + Math.floor(Math.random()*16777215).toString(16);
    }
};

const StringHelpers = {
    /**
     * Capitalize the first letter of each word in a string
     */
    capitalizeWords(str) {
        return str.replace(/\b\w/g, l => l.toUpperCase());
    },

    /**
     * Truncate a string to a specified length
     */
    truncate(str, length, ending = '...') {
        if (str.length > length) {
            return str.substring(0, length - ending.length) + ending;
        }
        return str;
    },

    /**
     * Strip HTML tags from a string
     */
    stripTags(str) {
        return str.replace(/<[^>]*>/g, '');
    }
};

const FileHelpers = {
    /**
     * Create and download a file
     */
    downloadFile(content, fileName, contentType) {
        const a = document.createElement("a");
        const file = new Blob([content], { type: contentType });
        a.href = URL.createObjectURL(file);
        a.download = fileName;
        a.click();
        URL.revokeObjectURL(a.href);
    },

    /**
     * Read a file as text
     */
    async readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }
};

// Initialize lazy loading
window.addEventListener('scroll', UIHelpers.debounce(() => {
    DOMHelpers.lazyLoadImages();
}, 200));

// Export all helpers
const Helpers = {
    UI: UIHelpers,
    DOM: DOMHelpers,
    Color: ColorHelpers,
    String: StringHelpers,
    File: FileHelpers
};

// Make helpers available globally
window.Helpers = Helpers;

/**
 * Event Listeners and DOM Ready Initialization
 */

const EventListeners = {
    init() {
        this.setupGlobalListeners();
        this.setupFormListeners();
        this.setupButtonListeners();
        this.setupModalListeners();
        this.setupScrollListeners();
    },

    setupGlobalListeners() {
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const modal = document.querySelector('.modal');
                if (modal && modal.style.display === 'block') {
                    modal.style.display = 'none';
                }
            }
        });

        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.style.display = 'none';
            }
        });
    },

    setupFormListeners() {
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') e.preventDefault();
            });
        });
    
        const urlInput = document.getElementById('url-input');
        if (urlInput) {
            urlInput.addEventListener('input', Helpers.UI.debounce((e) => {
                updateInputTypeIndicator(e.target.value.trim());
            }, 300));
        }
    
        const filterForm = document.getElementById('filter-form');
        if (filterForm) {
            filterForm.addEventListener('submit', (e) => {
                e.preventDefault(); // Prevent default form submission
                filterForm.submit();
            });
        }
    },

    setupButtonListeners() {
        const analyzeButton = document.getElementById('analyze-button');
        if (analyzeButton) {
            analyzeButton.addEventListener('click', analyzeInput);
        }

        const refreshButton = document.querySelector('.btn-refresh');
        if (refreshButton) {
            refreshButton.addEventListener('click', Helpers.UI.throttle(refreshActivity, 5000));
        }

        const exportButton = document.querySelector('.btn-export');
        if (exportButton) {
            exportButton.addEventListener('click', exportHistory);
        }

        const resetFiltersBtn = document.getElementById('reset-filters-btn');
        if (resetFiltersBtn) {
            resetFiltersBtn.addEventListener('click', () => {
                console.log('Reset filters button clicked');
                const filterForm = document.getElementById('filter-form');
                if (filterForm) {
                    console.log('Resetting form...');
                    // Reset all form inputs to their default values
                    filterForm.reset();
                    
                    // Reset select elements to their first option
                    filterForm.querySelectorAll('select').forEach(select => {
                        select.selectedIndex = 0;
                    });
    
                    // Reset date inputs
                    const dateFrom = filterForm.querySelector('[name="date_from"]');
                    const dateTo = filterForm.querySelector('[name="date_to"]');
                    if (dateFrom) dateFrom.value = '';
                    if (dateTo) dateTo.value = '';
    
                    console.log('Submitting form...');
                    // Submit the form
                    filterForm.submit();
                } else {
                    console.error('Filter form not found');
                }
            });
        } else {
            console.log('Reset filters button not found');
        }

        const Helpers = {
            File: {
                copyToClipboard: function(text) {
                    navigator.clipboard.writeText(text).then(function() {
                        alert('Copied to clipboard!');
                    }, function(err) {
                        console.error('Could not copy text: ', err);
                    });
                }
            }
        };
        
        document.querySelectorAll('.copy-btn').forEach(button => {
            button.addEventListener('click', function() {
                const text = this.getAttribute('data-clipboard-text');
                Helpers.File.copyToClipboard(text);
            });
        });
    },

    setupModalListeners() {
        document.querySelectorAll('.view-details-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const url = button.getAttribute('data-url');
                viewDetails(url);
            });
        });

        document.querySelectorAll('.reanalyze-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const url = button.getAttribute('data-url');
                reanalyze(url);
            });
        });
    },

    setupScrollListeners() {
        window.addEventListener('scroll', Helpers.UI.debounce(() => {
            Helpers.DOM.lazyLoadImages();
        }, 200));

        if (document.querySelector('.history-container')) {
            window.addEventListener('scroll', Helpers.UI.throttle(() => {
                const { scrollTop, scrollHeight, clientHeight } = document.documentElement;
                if (scrollTop + clientHeight >= scrollHeight - 5) {
                    // Load more history items if needed
                    // loadMoreHistory();
                }
            }, 500));
        }
    }
};

document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing application...');
    
    try {
        initializeCore();
        EventListeners.init();
        
        const chartData = window.chartData;
        if (document.querySelector('.dashboard') && chartData) {
            initializeDashboardCharts(chartData.trend_data, chartData.distribution_data);
        }
        
        if (document.querySelector('.history-container')) {
            initializeHistoryPage();
        }
        
        // Add debug logging
        if (document.getElementById('result')) {
            console.log('Found result element');
            const resultDataElement = document.getElementById('result-data');
            if (resultDataElement) {
                console.log('Found result data element');
                try {
                    const resultData = JSON.parse(resultDataElement.textContent);
                    console.log('Parsed result data:', resultData);
                    displayResult(resultData);
                } catch (e) {
                    console.error('Error parsing result data:', e);
                    console.log('Raw result data:', resultDataElement.textContent);
                }
            } else {
                console.error('Result data element not found');
            }
        }
        
        console.log('Application initialized successfully');
    } catch (error) {
        console.error('Error during initialization:', error);
        handleError(error, 'initialization');
    }
});

window.addEventListener('load', function() {
    Helpers.DOM.lazyLoadImages();
    
    const loadingScreen = document.getElementById('loading-screen');
    if (loadingScreen) {
        loadingScreen.style.display = 'none';
    }
});

window.addEventListener('resize', Helpers.UI.debounce(function() {
    if (document.querySelector('.dashboard')) {
        const chartData = window.chartData;
        initializeDashboardCharts(chartData?.trend_data, chartData?.distribution_data);
    }
}, 250));

window.addEventListener('beforeunload', function(e) {
    // Check for unsaved changes
    const hasUnsavedChanges = false; // Implement your check here
    
    if (hasUnsavedChanges) {
        e.preventDefault();
        e.returnValue = '';
    }
});

document.getElementById('feedback-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    // Disable the submit button immediately
    const submitButton = this.querySelector('button[type="submit"]');
    if (submitButton.disabled) {
        return; // Prevent duplicate submissions
    }
    submitButton.disabled = true;
    
    const formData = new FormData(this);
    console.log('Submitting form data:', Object.fromEntries(formData));

    fetch('/submit_feedback', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Feedback submitted successfully!');
            this.reset();
        } else {
            alert(data.message || 'Error submitting feedback. Please try again.');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    })
    .finally(() => {
        // Re-enable the submit button after processing is complete
        submitButton.disabled = false;
    });
});
