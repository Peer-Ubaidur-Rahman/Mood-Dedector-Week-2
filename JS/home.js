const API_BASE_URL = 'http://127.0.0.1:5000/api';

let stream = null;
let faceapiLoaded = false;
let currentSessionId = null;
let emotionCount = 0;

async function startCamera() {
    const statusDiv = document.getElementById('status');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const videoElement = document.getElementById('video');

    try {
        statusDiv.textContent = 'Requesting camera access...';
        statusDiv.className = 'status loading';

        stream = await navigator.mediaDevices.getUserMedia({
            video: {
                width: { ideal: 1280 },
                height: { ideal: 720 }
            }
        });

        videoElement.srcObject = stream;

        await new Promise((resolve) => {
            videoElement.onloadedmetadata = () => {
                resolve();
            };
        });

        await videoElement.play();

        startBtn.style.display = 'none';
        stopBtn.style.display = 'inline-block';

        statusDiv.textContent = 'Loading AI models...';

        if (!faceapiLoaded) {
            await loadFaceAPI();
            faceapiLoaded = true;
        }

        statusDiv.textContent = 'Camera active - Detecting emotions...';
        statusDiv.className = 'status success';

        await startSession();

        detectEmotions();
    } catch (error) {
        console.error('Camera error:', error);
        statusDiv.textContent = 'Camera access denied or unavailable';
        statusDiv.className = 'status error';
    }
}

async function stopCamera() {
    const statusDiv = document.getElementById('status');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const videoElement = document.getElementById('video');

    if (stream) {
        stream.getTracks().forEach(track => track.stop());
        stream = null;
    }

    videoElement.srcObject = null;

    startBtn.style.display = 'inline-block';
    stopBtn.style.display = 'none';

    statusDiv.textContent = 'Camera stopped';
    statusDiv.className = 'status';

    document.getElementById('emotion-name').textContent = '--';
    document.getElementById('emotion-emoji').textContent = '';
    document.getElementById('confidence').textContent = 'Confidence: 0%';

    const emotions = ['happy', 'sad', 'angry', 'surprised', 'fearful', 'disgusted', 'neutral'];
    emotions.forEach(emotion => {
        document.getElementById(emotion + '-bar').style.width = '0%';
        document.getElementById(emotion + '-percent').textContent = '0%';
    });

    await endSession();
}

async function loadFaceAPI() {
    const MODEL_URL = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api/model/';

    await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL);
    await faceapi.nets.faceExpressionNet.loadFromUri(MODEL_URL);
}

async function startSession() {
    const token = localStorage.getItem('token');
    if (!token) {
        console.log('User not logged in, skipping session tracking');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/sessions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();
        if (response.ok) {
            currentSessionId = data.session_id;
            emotionCount = 0;
            console.log('Session started:', currentSessionId);
        }
    } catch (error) {
        console.error('Error starting session:', error);
    }
}

async function endSession() {
    const token = localStorage.getItem('token');
    if (!token || !currentSessionId) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/sessions/${currentSessionId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                emotions_detected: emotionCount,
                end_session: true
            })
        });

        if (response.ok) {
            console.log('Session ended');
            currentSessionId = null;
        }
    } catch (error) {
        console.error('Error ending session:', error);
    }
}
async function saveEmotion(emotion, confidence) {
    const token = localStorage.getItem('token');
    if (!token) {
        console.log('User not logged in, skipping save');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/mood-records`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                emotion: emotion,
                confidence: confidence
            })
        });

        if (response.ok) {
            emotionCount++;
            console.log('Emotion saved:', emotion, confidence);
        }
    } catch (error) {
        console.error('Error saving emotion:', error);
    }
}

let lastSaveTime = 0;
const SAVE_INTERVAL = 5000;

async function detectEmotions() {
    const videoElement = document.getElementById('video');
    const statusDiv = document.getElementById('status');

    const detectFrame = async () => {
        if (!stream) return;

        try {
            const detections = await faceapi
                .detectSingleFace(videoElement, new faceapi.TinyFaceDetectorOptions())
                .withFaceExpressions();

            if (detections) {
                const expressions = detections.expressions;

                const emotionMap = {
                    happy: { emoji: '😊', name: 'Happy' },
                    sad: { emoji: '😢', name: 'Sad' },
                    angry: { emoji: '😠', name: 'Angry' },
                    surprised: { emoji: '😮', name: 'Surprised' },
                    fearful: { emoji: '😨', name: 'Fearful' },
                    disgusted: { emoji: '🤢', name: 'Disgusted' },
                    neutral: { emoji: '😐', name: 'Neutral' }
                };

                let maxEmotion = 'neutral';
                let maxValue = 0;

                for (const emotion in expressions) {
                    const value = expressions[emotion];
                    const percent = Math.round(value * 100);

                    const barId = emotion + '-bar';
                    const percentId = emotion + '-percent';

                    const barElement = document.getElementById(barId);
                    const percentElement = document.getElementById(percentId);

                    if (barElement && percentElement) {
                        barElement.style.width = percent + '%';
                        percentElement.textContent = percent + '%';
                    }

                    if (value > maxValue) {
                        maxValue = value;
                        maxEmotion = emotion;
                    }
                }

                const emotionData = emotionMap[maxEmotion];
                document.getElementById('emotion-name').textContent = emotionData.name;
                document.getElementById('emotion-emoji').textContent = emotionData.emoji;
                document.getElementById('confidence').textContent = 
                    'Confidence: ' + Math.round(maxValue * 100) + '%';

                statusDiv.textContent = 'Detecting emotions...';
                statusDiv.className = 'status success';

                const now = Date.now();
                if (now - lastSaveTime >= SAVE_INTERVAL) {
                    await saveEmotion(maxEmotion, maxValue);
                    lastSaveTime = now;
                }
            } else {
                statusDiv.textContent = 'No face detected';
                statusDiv.className = 'status warning';
            }
        } catch (error) {
            console.error('Detection error:', error);
        }

        requestAnimationFrame(detectFrame);
    };

    detectFrame();
}

document.addEventListener('DOMContentLoaded', function() {
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');

    if (startBtn) {
        startBtn.addEventListener('click', startCamera);
    }

    if (stopBtn) {
        stopBtn.addEventListener('click', stopCamera);
    }
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        const userData = JSON.parse(user);
        console.log('Welcome back,', userData.fullname);
    } else {
        console.log('Not logged in - mood records will not be saved');
    }
});
