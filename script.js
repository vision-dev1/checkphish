// codes by vision
const API_BASE_URL = window.location.origin === 'null' || window.location.protocol === 'file:'
    ? 'http://localhost:5000'
    : window.location.origin;

function showSection(section) {
    const sections = document.querySelectorAll('.section-content');
    sections.forEach(s => s.classList.add('hidden'));

    const targetSection = document.getElementById(`${section}-section`);
    if (targetSection) {
        targetSection.classList.remove('hidden');
    }
}

function showLoading(buttonElement) {
    if (!buttonElement) return;
    buttonElement.disabled = true;
    buttonElement.innerHTML = '<span class="spinner"></span>Analyzing...';
}

function hideLoading(buttonElement, originalText) {
    if (!buttonElement) return;
    buttonElement.disabled = false;
    buttonElement.innerHTML = originalText;
}

function displayResult(resultElement, data, type) {
    if (!resultElement) return;
    resultElement.classList.remove('hidden', 'success', 'danger', 'warning');

    const isPhishing = data.result === 'Phishing';
    const resultClass = isPhishing ? 'danger' : 'success';
    resultElement.classList.add(resultClass);

    const icon = isPhishing ? '⚠️' : '✅';
    const resultText = isPhishing ? 'Phishing Detected' : 'Legitimate';
    const color = isPhishing ? '#dc2626' : '#16a34a';

    let html = `
        <div class="flex items-start gap-4">
            <span style="font-size: 2rem;">${icon}</span>
            <div class="flex-1">
                <h5 class="text-lg font-bold mb-2" style="color: ${color};">${resultText}</h5>
                <p class="text-sm mb-2"><strong>Confidence:</strong> ${data.confidence}</p>
    `;

    if (data.decoded_url) {
        html += `<p class="text-sm mb-2"><strong>Decoded URL:</strong> <code class="bg-gray-100 px-2 py-1 rounded text-xs">${data.decoded_url}</code></p>`;
    }

    if (data.warning) {
        html += `<p class="text-xs text-amber-600 mt-2">⚠️ ${data.warning}</p>`;
    }

    if (isPhishing) {
        html += `
            <div class="mt-4 p-3 bg-red-50 rounded border border-red-200">
                <p class="text-xs font-semibold text-red-800 mb-1">⚠️ Security Recommendation:</p>
                <p class="text-xs text-red-700">Do not click any links, download attachments, or provide personal information. Report this to your IT security team.</p>
            </div>
        `;
    } else {
        html += `
            <div class="mt-4 p-3 bg-green-50 rounded border border-green-200">
                <p class="text-xs font-semibold text-green-800 mb-1">✓ Analysis Complete</p>
                <p class="text-xs text-green-700">This appears to be legitimate, but always exercise caution and verify the source.</p>
            </div>
        `;
    }

    html += `
            </div>
        </div>
    `;

    resultElement.innerHTML = html;

    incrementCounter('scans-counter');
}

function displayError(resultElement, errorMessage) {
    if (!resultElement) return;
    resultElement.classList.remove('hidden', 'success', 'danger');
    resultElement.classList.add('warning');

    resultElement.innerHTML = `
        <div class="flex items-start gap-4">
            <span style="font-size: 2rem;">⚠️</span>
            <div>
                <h5 class="text-lg font-bold mb-2 text-amber-700">Error</h5>
                <p class="text-sm">${errorMessage}</p>
            </div>
        </div>
    `;
}

async function analyzeEmail(event) {
    if (event) event.preventDefault();
    const emailText = document.getElementById('email-text').value.trim();
    const resultElement = document.getElementById('email-result');
    const button = event ? event.target : null;

    if (!emailText) {
        displayError(resultElement, 'Please enter email content to analyze.');
        return;
    }

    showLoading(button);

    try {
        const response = await fetch(`${API_BASE_URL}/detect/email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ text: emailText })
        });

        const data = await response.json();

        if (response.ok) {
            displayResult(resultElement, data, 'email');
        } else {
            displayError(resultElement, data.error || 'Failed to analyze email');
        }
    } catch (error) {
        displayError(resultElement, 'Network error. Please ensure the backend server is running.');
    } finally {
        hideLoading(button, 'Analyze Email');
    }
}

async function analyzeURL(event) {
    if (event) event.preventDefault();
    const urlInput = document.getElementById('url-input').value.trim();
    const resultElement = document.getElementById('url-result');
    const button = event ? event.target : null;

    if (!urlInput) {
        displayError(resultElement, 'Please enter a URL to analyze.');
        return;
    }

    showLoading(button);

    try {
        const response = await fetch(`${API_BASE_URL}/detect/url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: urlInput })
        });

        const data = await response.json();

        if (response.ok) {
            displayResult(resultElement, data, 'url');
        } else {
            displayError(resultElement, data.error || 'Failed to analyze URL');
        }
    } catch (error) {
        displayError(resultElement, 'Network error. Please ensure the backend server is running.');
    } finally {
        hideLoading(button, 'Check URL');
    }
}

async function analyzeQR(event) {
    if (event) event.preventDefault();
    const fileInput = document.getElementById('qr-file-input');
    const resultElement = document.getElementById('qr-result');
    const button = event ? event.target : null;

    if (!fileInput.files || fileInput.files.length === 0) {
        displayError(resultElement, 'Please select a QR code image to scan.');
        return;
    }

    showLoading(button);

    const formData = new FormData();
    formData.append('image', fileInput.files[0]);

    try {
        const response = await fetch(`${API_BASE_URL}/detect/qr`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            displayResult(resultElement, data, 'qr');
        } else {
            displayError(resultElement, data.error || 'Failed to scan QR code');
        }
    } catch (error) {
        displayError(resultElement, 'Network error. Please ensure the backend server is running.');
    } finally {
        hideLoading(button, 'Scan Image');
    }
}

const dropZone = document.getElementById('qr-drop-zone');
const fileInput = document.getElementById('qr-file-input');
const filenameDisplay = document.getElementById('qr-filename');

dropZone.addEventListener('click', () => {
    fileInput.click();
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');

    if (e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        updateFilename(e.dataTransfer.files[0].name);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        updateFilename(e.target.files[0].name);
    }
});

function updateFilename(filename) {
    filenameDisplay.textContent = `Selected: ${filename}`;
}

function animateCounter(element, target, duration = 2000) {
    const start = 0;
    const increment = target / (duration / 16);
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            element.textContent = target.toLocaleString();
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current).toLocaleString();
        }
    }, 16);
}

function incrementCounter(counterId) {
    const counter = document.getElementById(counterId);
    const currentValue = parseInt(counter.textContent.replace(/,/g, '')) || 0;
    counter.textContent = (currentValue + 1).toLocaleString();
}

function initTheme() {
    const themeToggleBtn = document.getElementById('theme-toggle');
    const themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
    const themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');

    if (localStorage.getItem('color-theme') === 'dark' || (!('color-theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        themeToggleLightIcon.classList.remove('hidden');
        themeToggleDarkIcon.classList.add('hidden');
        document.documentElement.classList.add('dark');
    } else {
        themeToggleLightIcon.classList.add('hidden');
        themeToggleDarkIcon.classList.remove('hidden');
        document.documentElement.classList.remove('dark');
    }

    themeToggleBtn.addEventListener('click', function () {

        themeToggleDarkIcon.classList.toggle('hidden');
        themeToggleLightIcon.classList.toggle('hidden');

        if (localStorage.getItem('color-theme')) {
            if (localStorage.getItem('color-theme') === 'light') {
                document.documentElement.classList.add('dark');
                localStorage.setItem('color-theme', 'dark');
            } else {
                document.documentElement.classList.remove('dark');
                localStorage.setItem('color-theme', 'light');
            }

        } else {
            if (document.documentElement.classList.contains('dark')) {
                document.documentElement.classList.remove('dark');
                localStorage.setItem('color-theme', 'light');
            } else {
                document.documentElement.classList.add('dark');
                localStorage.setItem('color-theme', 'dark');
            }
        }
    });
}

function initScrollReveal() {
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                if (entry.target.classList.contains('fade-in-up-stagger')) {
                    const children = entry.target.querySelectorAll('.stagger-item');
                    children.forEach((child, index) => {
                        setTimeout(() => {
                            child.classList.add('active');
                        }, index * 100);
                    });
                }
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    document.querySelectorAll('.reveal, .fade-in-up-stagger').forEach(el => {
        observer.observe(el);
    });
}

document.addEventListener('DOMContentLoaded', () => {

    animateCounter(document.getElementById('scans-counter'), 12482);
    animateCounter(document.getElementById('users-counter'), 8200);
    animateCounter(document.getElementById('orgs-counter'), 450);

    initTheme();
    initScrollReveal();
});
