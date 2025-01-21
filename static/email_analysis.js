document.addEventListener('DOMContentLoaded', function() {
    // File upload form handling
    const form = document.getElementById('email-analysis-form');
    
    if (form) {
        const fileInput = form.querySelector('#email-file');
        const fileLabel = form.querySelector('.file-upload-label');
        const fileLabelText = fileLabel.querySelector('.label-text');
        const fileNameDisplay = form.querySelector('.file-name-display');
        const submitButton = form.querySelector('.btn-analyze');

        // File input change handler
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const fileName = file.name.toLowerCase();
                if (fileName.endsWith('.msg') || fileName.endsWith('.eml')) {
                    fileNameDisplay.textContent = `Selected file: ${file.name}`;
                    fileNameDisplay.style.display = 'block';
                    fileLabelText.textContent = 'Change File';
                    
                    // Add upload progress animation
                    fileLabel.classList.add('uploading');
                    
                    // Remove progress bar after animation
                    setTimeout(() => {
                        fileLabel.classList.remove('uploading');
                    }, 2000);
                } else {
                    alert('Please select a .msg or .eml file.');
                    fileInput.value = ''; // Clear the file input
                    fileNameDisplay.style.display = 'none';
                    fileLabelText.textContent = 'Choose File';
                }
            } else {
                fileNameDisplay.style.display = 'none';
                fileLabelText.textContent = 'Choose File';
            }
        });

        // Form submit handler
        form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!fileInput.files.length) {
                alert('Please select a file to analyze.');
                return;
            }

            submitButton.textContent = 'Analyzing...';
            submitButton.disabled = true;
            
            const formData = new FormData(form);
            
            try {
                const response = await fetch(form.action, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }

                const data = await response.json();
                if (data.error) {
                    alert(data.error);
                } else if (data.redirect) {
                    window.location.href = data.redirect;
                }
            } catch (error) {
                console.error('Error:', error);
                alert('An error occurred during analysis. Please try again.');
            } finally {
                submitButton.innerHTML = '<i class="fas fa-search"></i> Analyze Email';
                submitButton.disabled = false;
            }
        });
    }

    // Tab functionality
    function switchTab(tabName) {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');
        
        // Remove active class from all tabs and contents
        tabButtons.forEach(button => button.classList.remove('active'));
        tabContents.forEach(content => content.classList.remove('active'));
        
        // Add active class to selected tab and content
        const selectedButton = document.querySelector(`.tab-button[data-tab="${tabName}"]`);
        const selectedContent = document.getElementById(`${tabName}-view`);
        
        if (selectedButton && selectedContent) {
            selectedButton.classList.add('active');
            selectedContent.classList.add('active');
        }
    }

    // Initialize tab functionality
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            switchTab(this.dataset.tab);
        });
    });

    // Show text view by default
    switchTab('text');
});