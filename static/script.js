/* --- AURA Frontend Logic --- */
document.addEventListener('DOMContentLoaded', () => {
    // Get references to all the necessary HTML elements
    const imageInput = document.getElementById('image-input');
    const uploadButton = document.getElementById('upload-button');
    const fileNameDisplay = document.getElementById('file-name');
    const resultsContainer = document.getElementById('results-container');
    const summaryCard = document.getElementById('summary-card');
    const detailsGrid = document.getElementById('details-grid');
    const loader = document.getElementById('loader');
    const errorMessage = document.getElementById('error-message');
    
    // --- NEW: Add a container for visual artifacts ---
    const visualsContainer = document.createElement('div');
    visualsContainer.className = 'visuals-container';
    resultsContainer.appendChild(visualsContainer);


    // When the main upload button is clicked, trigger the hidden file input
    uploadButton.addEventListener('click', () => {
        imageInput.click();
    });

    // When a file is selected in the input, start the analysis
    imageInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            fileNameDisplay.textContent = file.name;
            handleImageUpload(file);
        }
    });

    /**
     * Handles the file upload and communication with the backend.
     * @param {File} file The image file to be analyzed.
     */
    async function handleImageUpload(file) {
        // 1. Reset the UI to a clean state
        resultsContainer.classList.add('hidden');
        errorMessage.classList.add('hidden');
        visualsContainer.classList.add('hidden'); // Hide visuals
        visualsContainer.innerHTML = ''; // Clear old visuals
        loader.classList.remove('hidden');

        // 2. Prepare the file to be sent to the server
        const formData = new FormData();
        formData.append('file', file);

        try {
            // 3. Send the file to the '/analyze' endpoint on the Python server
            const response = await fetch('/analyze', {
                method: 'POST',
                body: formData,
            });

            const results = await response.json();

            // 4. Check for errors from the server
            if (!response.ok) {
                throw new Error(results.error || 'An unknown error occurred on the server.');
            }
            
            // 5. If successful, display the results
            displayResults(results);

        } catch (error) {
            // If anything goes wrong, show an error message
            showError(error.message);
        } finally {
            // 6. Always hide the loader when done
            loader.classList.add('hidden');
            // Clear the file input to allow re-uploading the same file
            imageInput.value = '';
        }
    }

    /**
     * Dynamically populates the HTML with the analysis results.
     * @param {object} results The JSON object returned from the server.
     */
    function displayResults(results) {
        // Clear any previous results
        summaryCard.innerHTML = '';
        detailsGrid.innerHTML = '';
        visualsContainer.innerHTML = ''; // Clear visuals

        // --- 1. Populate the main Summary Card ---
        const prediction = results.Prediction || 'Unknown';
        const probability = results.AI_Probability_Score;
        const confidence = results.Confidence || 'N/A';

        const summaryTitle = document.createElement('h2');
        summaryTitle.textContent = prediction;
        
        const summaryProb = document.createElement('p');
        if (typeof probability === 'number') {
            summaryProb.textContent = `AI Probability: ${(probability * 100).toFixed(1)}% (Confidence: ${confidence})`;
        }
        
        summaryCard.appendChild(summaryTitle);
        summaryCard.appendChild(summaryProb);

        // Set the summary card's color based on the prediction
        if (prediction === 'AI-Generated') {
            summaryCard.style.backgroundColor = 'var(--danger-color)';
        } else if (prediction === 'Potentially AI') {
            summaryCard.style.backgroundColor = 'var(--warning-color)';
        } else {
            summaryCard.style.backgroundColor = 'var(--success-color)';
        }

        // --- 2. Populate the Detailed Forensic Grid ---
        // --- UPDATED: Added new Hexdump keys to the order and map ---
        const keyOrder = [
            "Reasoning", "Metadata_Hits", "Camera_Info",
            "Hex_Found_AI_Strings", "Hex_Found_Camera_Strings", "Hex_Found_PNG_tEXt", // <-- NEW HEX KEYS
            "FFT_Score", "Noise_StdDev", "ELA_MaxDiff", "Block_Boundary_Energy",
            "Sat_Mean", "Sat_Std", "Brightness_Mean", "Brightness_Std", "FileName"
        ];
        
        const keyMap = {
            Reasoning: "Primary Evidence",
            Metadata_Hits: "AI Metadata Keywords",
            Camera_Info: "Camera Info",
            Hex_Found_AI_Strings: "Hex: AI Keywords Found", // <-- NEW
            Hex_Found_Camera_Strings: "Hex: Camera Keywords Found", // <-- NEW
            Hex_Found_PNG_tEXt: "Hex: PNG 'tEXt' Chunk", // <-- NEW
            FFT_Score: "FFT Score (Frequency)",
            Noise_StdDev: "Noise Variation",
            ELA_MaxDiff: "ELA Score (Recompression)",
            Block_Boundary_Energy: "JPEG Block Artifacts",
            Sat_Mean: "Avg. Saturation",
            Sat_Std: "Saturation Variation",
            Brightness_Mean: "Avg. Brightness",
            Brightness_Std: "Brightness Variation",
            FileName: "File Name"
        };
        
        keyOrder.forEach(key => {
            if (results[key] !== undefined && results[key] !== null && results[key] !== "") {
                const item = document.createElement('div');
                item.className = 'detail-item';

                const keySpan = document.createElement('span');
                keySpan.className = 'key';
                keySpan.textContent = keyMap[key] || key;

                const valueSpan = document.createElement('span');
                valueSpan.className = 'value';
                
                let value = results[key];
                if (typeof value === 'number') {
                    value = value.toFixed(4);
                }
                valueSpan.textContent = value;

                item.appendChild(keySpan);
                item.appendChild(valueSpan);
                detailsGrid.appendChild(item);
            }
        });
        
        // --- 3. Populate Visual Artifacts ---
        const visuals = [
            { key: 'FFT_Visual', title: 'Frequency Spectrum (FFT)' },
            { key: 'Noise_Visual', title: 'Noise Residual Map' },
            { key: 'ELA_Visual', title: 'Error Level Analysis (ELA)' }
        ];

        let hasVisuals = false;
        visuals.forEach(vis => {
            if (results[vis.key]) {
                hasVisuals = true;
                const visualCard = document.createElement('div');
                visualCard.className = 'visual-card';

                const title = document.createElement('h3');
                title.textContent = vis.title;

                const img = document.createElement('img');
                img.src = `data:image/png;base64,${results[vis.key]}`;
                
                visualCard.appendChild(title);
                visualCard.appendChild(img);
                visualsContainer.appendChild(visualCard);
            }
        });
        
        if (hasVisuals) {
            const visualsHeader = document.createElement('h2');
            visualsHeader.textContent = 'Forensic Visualizations';
            visualsContainer.prepend(visualsHeader);
            visualsContainer.classList.remove('hidden');
        }


        // Finally, show the results container
        resultsContainer.classList.remove('hidden');
    }

    /**
     * Displays an error message in the UI.
     * @param {string} message The error message to display.
     */
    function showError(message) {
        errorMessage.textContent = `Analysis Failed: ${message}`;
        errorMessage.classList.remove('hidden');
    }
});