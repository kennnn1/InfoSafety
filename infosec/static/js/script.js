// wait for dom to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // tab functionality
    const tabs = document.querySelectorAll('.tab');
    if (tabs.length > 0) {
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // remove active class from all tabs
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                
                // add active class to clicked tab
                tab.classList.add('active');
                
                // hide all tab contents
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.remove('active');
                });
                
                // show the selected tab content
                const tabId = tab.getAttribute('data-tab');
                document.getElementById(`${tabId}-content`).classList.add('active');
            });
        });
    }
    
    // algorithm selection cards
    const algoCards = document.querySelectorAll('.algo-selection .algo-card');
    if (algoCards.length > 0) {
        algoCards.forEach(card => {
            card.addEventListener('click', () => {
                // remove selected class from all cards
                algoCards.forEach(c => c.classList.remove('selected'));
                
                // add selected class to clicked card
                card.classList.add('selected');
                
                // update hidden input with selected algorithm
                const algoInput = document.getElementById('algorithm');
                if (algoInput) {
                    algoInput.value = card.getAttribute('data-algorithm');
                }
            });
        });
    }
    
    // file upload styling
    const fileInputs = document.querySelectorAll('input[type="file"]');
    if (fileInputs.length > 0) {
        fileInputs.forEach(input => {
            input.addEventListener('change', function() {
                const fileName = this.files[0] ? this.files[0].name : 'No file chosen';
                const fileNameElement = this.parentElement.querySelector('.file-name');
                
                if (fileNameElement) {
                    fileNameElement.textContent = fileName;
                }
            });
        });
    }
    
    // form submission loading state
    const forms = document.querySelectorAll('form');
    if (forms.length > 0) {
        forms.forEach(form => {
            form.addEventListener('submit', function() {
                const submitBtn = this.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
                    submitBtn.disabled = true;
                }
                
                const loadingElement = document.querySelector('.loading-container');
                if (loadingElement) {
                    loadingElement.classList.add('loading');
                }
            });
        });
    }
    
    // copy to clipboard functionality
    const copyButtons = document.querySelectorAll('.copy-btn');
    if (copyButtons.length > 0) {
        copyButtons.forEach(button => {
            button.addEventListener('click', function() {
                const contentToCopy = this.getAttribute('data-copy');
                if (contentToCopy) {
                    navigator.clipboard.writeText(contentToCopy)
                        .then(() => {
                            const originalText = this.textContent;
                            this.textContent = 'Copied!';
                            setTimeout(() => {
                                this.textContent = originalText;
                            }, 2000);
                        })
                        .catch(err => {
                            console.error('Failed to copy text: ', err);
                        });
                }
            });
        });
    }
    
    // text/file toggle in encrypt/decrypt forms
    const inputTypeRadios = document.querySelectorAll('input[name="input_type"]');
    if (inputTypeRadios.length > 0) {
        inputTypeRadios.forEach(radio => {
            radio.addEventListener('change', function() {
                const textInput = document.getElementById('text-input-container');
                const fileInput = document.getElementById('file-input-container');
                
                if (this.value === 'text' && textInput && fileInput) {
                    textInput.style.display = 'block';
                    fileInput.style.display = 'none';
                } else if (this.value === 'file' && textInput && fileInput) {
                    textInput.style.display = 'none';
                    fileInput.style.display = 'block';
                }
            });
        });
    }
    
    // qr code tab functionality
    const qrTab = document.getElementById('qr-tab');
    const textTab = document.getElementById('text-tab');
    
    if (qrTab && textTab) {
        qrTab.addEventListener('click', () => {
            document.getElementById('qr-output').style.display = 'block';
            document.getElementById('text-output').style.display = 'none';
            qrTab.classList.add('active');
            textTab.classList.remove('active');
        });
        
        textTab.addEventListener('click', () => {
            document.getElementById('qr-output').style.display = 'none';
            document.getElementById('text-output').style.display = 'block';
            textTab.classList.add('active');
            qrTab.classList.remove('active');
        });
    }
    
    // key strength meter
    const keyInput = document.getElementById('key');
    const strengthMeter = document.getElementById('key-strength');
    
    if (keyInput && strengthMeter) {
        keyInput.addEventListener('input', function() {
            const key = this.value;
            let strength = 'weak';
            let color = '#e74c3c';
            
            if (key.length >= 8) {
                if (/[A-Z]/.test(key) && /[a-z]/.test(key) && /[0-9]/.test(key) && /[^A-Za-z0-9]/.test(key)) {
                    strength = 'strong';
                    color = '#2ecc71';
                } else if ((/[A-Z]/.test(key) || /[a-z]/.test(key)) && /[0-9]/.test(key)) {
                    strength = 'medium';
                    color = '#f39c12';
                }
            }
            
            strengthMeter.textContent = `Key strength: ${strength}`;
            strengthMeter.style.color = color;
        });
    }
});

// confirm before resetting form
function confirmReset() {
    return confirm("Are you sure you want to reset all fields?");
}

// generate random key
function generateRandomKey(length) {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    let key = "";
    
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        key += charset[randomIndex];
    }
    
    document.getElementById('key').value = key;
    
    //  key strength update
    const event = new Event('input');
    document.getElementById('key').dispatchEvent(event);
    
    return false;
}

// see the password
function togglePasswordVisibility() {
    const keyInput = document.getElementById('key');
    const toggleIcon = document.getElementById('toggleIcon');
    
    if (keyInput.type === 'password') {
        keyInput.type = 'text';
        toggleIcon.classList.remove('fa-eye');
        toggleIcon.classList.add('fa-eye-slash');
    } else {
        keyInput.type = 'password';
        toggleIcon.classList.remove('fa-eye-slash');
        toggleIcon.classList.add('fa-eye');
    }
}