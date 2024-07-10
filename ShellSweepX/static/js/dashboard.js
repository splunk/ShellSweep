// Chart initialization
function initCharts() {
    console.log('Initializing charts...');
    fetch('/api/chart_data')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Received chart data:', data);
            const trendCtx = document.getElementById('detectionTrendChart').getContext('2d');
            const pieCtx = document.getElementById('webshellTypesPieChart').getContext('2d');

            if (!data || !data.trend || !data.types || data.trend.labels.length === 0 || data.types.labels.length === 0) {
                console.error('Invalid or empty chart data received');
                return;
            }

            try {
                new Chart(trendCtx, {
                    type: 'line',
                    data: {
                        labels: data.trend.labels,
                        datasets: [{
                            label: 'Detections',
                            data: data.trend.data,
                            borderColor: 'rgb(75, 192, 192)',
                            tension: 0.1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Detection Trend'
                            }
                        }
                    }
                });

                new Chart(pieCtx, {
                    type: 'pie',
                    data: {
                        labels: data.types.labels,
                        datasets: [{
                            data: data.types.data,
                            backgroundColor: [
                                'rgb(255, 99, 132)',
                                'rgb(54, 162, 235)',
                                'rgb(255, 205, 86)',
                                'rgb(75, 192, 192)',
                                'rgb(153, 102, 255)',
                                'rgb(255, 159, 64)'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Webshell Types Distribution'
                            },
                            legend: {
                                position: 'right'
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error creating charts:', error);
            }
        })
        .catch(error => {
            console.error('Error fetching or processing chart data:', error);
            // Optionally, display an error message to the user
            const chartContainers = document.querySelectorAll('.chart-container');
            chartContainers.forEach(container => {
                container.innerHTML = '<p>Error loading chart data. Please try refreshing the page.</p>';
            });
        });
}

function updateRecentDetections() {
    const detectionsList = document.getElementById('detections-list');
    fetch('/api/recent_detections')
        .then(response => response.json())
        .then(data => {
            detectionsList.innerHTML = '';
            data.forEach(detection => {
                const detectionItem = document.createElement('div');
                detectionItem.className = 'detection-item';
                detectionItem.innerHTML = `
                    <span class="severity-indicator ${getSeverityClass(detection.severity)}"></span>
                    <span>${detection.file_name}</span>
                    <span>Detected: ${detection.detected_time}</span>
                    <button class="view-details" onclick="viewDetails('${detection.id}')">View Details</button>
                `;
                detectionsList.appendChild(detectionItem);
            });
        });
}

function getSeverityClass(severity) {
    switch(severity) {
        case 'high': return 'severity-high';
        case 'medium': return 'severity-medium';
        case 'low': return 'severity-low';
        default: return 'severity-unknown';
    }
}

function viewDetails(id) {
    window.location.href = `/analysis?id=${id}`;
}

function updateLastUpdated() {
    const lastUpdatedSpan = document.getElementById('last-updated-time');
    lastUpdatedSpan.textContent = new Date().toLocaleString();
}

let socket;

function connectWebSocket() {
    socket = new WebSocket('ws://localhost:8080/ws');
    
    socket.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if (data.type === 'new_detection') {
            updateRecentDetections();
            updateLastUpdated();
        }
    };

    socket.onclose = function(event) {
        console.log('WebSocket connection closed. Reconnecting...');
        setTimeout(connectWebSocket, 3000);
    };
}

document.addEventListener('DOMContentLoaded', function() {
    initCharts();
    updateRecentDetections();
    updateLastUpdated();
    connectWebSocket();
    setInterval(updateLastUpdated, 60000);
});