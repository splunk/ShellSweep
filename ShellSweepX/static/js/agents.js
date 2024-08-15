async function loadAgents() {
    try {
        const response = await fetch('/api/agents');
        const agents = await response.json();
        const tableBody = document.querySelector('#agent-table tbody');
        tableBody.innerHTML = '';
        if (agents.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="2">No agents found</td>';
            tableBody.appendChild(row);
        } else {
            const uniqueAgents = new Map();
            agents.forEach(agent => {
                if (!uniqueAgents.has(agent.computer_name) || 
                    agent.last_checkin > uniqueAgents.get(agent.computer_name).last_checkin) {
                    uniqueAgents.set(agent.computer_name, agent);
                }
            });

            uniqueAgents.forEach(agent => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${agent.computer_name}</td>
                    <td>${new Date(agent.last_checkin).toLocaleString()}</td>
                `;
                tableBody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

async function loadConfiguration() {
    try {
        const response = await fetch('/api/agent_config');
        const config = await response.json();
        
        console.log('Loaded configuration:', config);

        const fileExtensionsContainer = document.getElementById('file-extensions-container');
        if (!fileExtensionsContainer) {
            console.error('File extensions container not found');
            return;
        }
        fileExtensionsContainer.innerHTML = '';
        
        for (const [ext, conditions] of Object.entries(config.file_extensions)) {
            addFileExtensionField(ext, conditions);
        }
        
        const directoryPaths = document.getElementById('directory-paths');
        const excludePaths = document.getElementById('exclude-paths');
        const ignoreHashes = document.getElementById('ignore-hashes');
        
        if (directoryPaths) {
            directoryPaths.value = config.directory_paths.join('\n');
        } else {
            console.error('Directory paths textarea not found');
        }
        
        if (excludePaths) {
            excludePaths.value = config.exclude_paths.join('\n');
        } else {
            console.error('Exclude paths textarea not found');
        }
        
        if (ignoreHashes) {
            ignoreHashes.value = config.ignore_hashes.join('\n');
        } else {
            console.error('Ignore hashes textarea not found');
        }
    } catch (error) {
        console.error('Error loading configuration:', error);
    }
}

function addFileExtensionField(ext = '', conditions = []) {
    const container = document.getElementById('file-extensions-container');
    const extDiv = document.createElement('div');
    extDiv.className = 'file-extension';
    extDiv.innerHTML = `
        <input type="text" class="ext-name" value="${ext}" placeholder="Extension (e.g., .php)">
        <div class="conditions"></div>
        <button type="button" onclick="addCondition(this)">Add Condition</button>
        <button type="button" onclick="removeFileExtension(this)">Remove Extension</button>
    `;
    container.appendChild(extDiv);
    
    conditions.forEach(condition => {
        addConditionField(extDiv.querySelector('.conditions'), condition.operation, condition.value);
    });
}

function addFileExtension() {
    addFileExtensionField();
}

function addCondition(button) {
    const conditionsDiv = button.parentElement.querySelector('.conditions');
    addConditionField(conditionsDiv);
}

function addConditionField(container, operation = 'gt', value = '') {
    const conditionDiv = document.createElement('div');
    conditionDiv.className = 'condition';
    conditionDiv.innerHTML = `
        <select class="condition-op">
            <option value="gt" ${operation === 'gt' ? 'selected' : ''}>Greater Than</option>
            <option value="lt" ${operation === 'lt' ? 'selected' : ''}>Less Than</option>
        </select>
        <input type="number" class="condition-value" value="${value}" step="0.01">
        <button type="button" onclick="removeCondition(this)">Remove</button>
    `;
    container.appendChild(conditionDiv);
}

function removeFileExtension(button) {
    button.parentElement.remove();
}

function removeCondition(button) {
    button.parentElement.remove();
}

async function saveConfiguration(event) {
    event.preventDefault();
    console.log('saveConfiguration called');

    const directoryPaths = document.getElementById('directory-paths');
    const excludePaths = document.getElementById('exclude-paths');
    const ignoreHashes = document.getElementById('ignore-hashes');

    if (!directoryPaths || !excludePaths || !ignoreHashes) {
        console.error('One or more required elements not found');
        return;
    }

    const config = {
        file_extensions: {},
        directory_paths: directoryPaths.value.split('\n').filter(Boolean),
        exclude_paths: excludePaths.value.split('\n').filter(Boolean),
        ignore_hashes: ignoreHashes.value.split('\n').filter(Boolean)
    };
    
    const fileExtensions = document.querySelectorAll('.file-extension');
    fileExtensions.forEach(extDiv => {
        const extName = extDiv.querySelector('.ext-name');
        const conditions = [];
        extDiv.querySelectorAll('.condition').forEach(conditionDiv => {
            const op = conditionDiv.querySelector('.condition-op');
            const value = conditionDiv.querySelector('.condition-value');
            if (op && value) {
                conditions.push({
                    operation: op.value,
                    value: parseFloat(value.value)
                });
            }
        });
        if (extName && extName.value && conditions.length > 0) {
            config.file_extensions[extName.value] = conditions;
        }
    });
    
    console.log('Saving configuration:', config);
    
    try {
        const response = await fetch('/api/agent_config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
        if (response.ok) {
            const result = await response.json();
            alert(result.message);
            await loadConfiguration();
        } else {
            const errorData = await response.json();
            alert(`Failed to save configuration: ${errorData.detail}`);
        }
    } catch (error) {
        console.error('Error saving configuration:', error);
        alert('An error occurred while saving the configuration');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOMContentLoaded event fired');
    loadAgents();
    loadConfiguration();
    const configForm = document.getElementById('config-form');
    if (configForm) {
        console.log('Config form found');
        configForm.addEventListener('submit', async (event) => {
            console.log('Form submitted');
            event.preventDefault();
            await saveConfiguration(event);
        });
    } else {
        console.error('Config form not found');
    }
    const addFileExtensionButton = document.querySelector('button[onclick="addFileExtension()"]');
    if (addFileExtensionButton) {
        console.log('Add File Extension button found');
        addFileExtensionButton.addEventListener('click', addFileExtension);
    } else {
        console.error('Add File Extension button not found');
    }
});