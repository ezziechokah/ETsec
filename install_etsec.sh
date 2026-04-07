# install_etsec.sh
#!/bin/bash

echo "Installing ETsec Security System..."

# Install Python dependencies
pip install opencv-python face-recognition numpy flask flask-socketio pywhatkit sqlite3

# Create directory structure
mkdir -p captures templates static/logs

# Download Iriun Webcam from https://iriun.com/
echo "Please install Iriun Webcam on your laptop and phones"

# Create startup script
cat > start_etsec.sh << 'EOF'
#!/bin/bash
python3 etsec_main.py
EOF

chmod +x start_etsec.sh

echo "Installation complete!"
echo "Run './start_etsec.sh' to start the system"
echo "Access dashboard at http://localhost:5000"
echo "Default login: admin / ezzietech"