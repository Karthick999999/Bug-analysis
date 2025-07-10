# AutoRedTeam Web Application

A modern web-based interface for the AutoRedTeam vulnerability scanner, providing an intuitive way to scan websites for security vulnerabilities.

## 🚀 Features

- **Modern Web Interface**: Clean, responsive design with real-time updates
- **Real-time Scanning**: Live progress updates during vulnerability scans
- **Professional Reports**: Download results in PDF or JSON format
- **Multiple Scan Options**: Customize URL limits and scan delays
- **Security Focused**: Built-in warnings and ethical guidelines
- **Cross-platform**: Works on any modern web browser

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Modern web browser (Chrome, Firefox, Safari, Edge)

## 🛠️ Installation

### 1. Clone or Download the Project
```bash
# If you have the project locally, navigate to the web directory
cd autoredteam-website
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Verify Installation
```bash
python backend/app.py --help
```

## 🎯 Quick Start

### 1. Start the Backend Server
```bash
cd backend
python app.py
```
The server will start on `http://localhost:5000`

### 2. Open the Frontend
Open `frontend/index.html` in your web browser, or serve it using a local server:

```bash
# Using Python's built-in server
cd frontend
python -m http.server 8000
```

Then visit `http://localhost:8000`

### 3. Start Scanning
1. Enter a target website URL
2. Adjust scan parameters if needed
3. Click "Start Scan"
4. Watch real-time progress
5. View results and download reports

## 📁 Project Structure

```
autoredteam-website/
├── frontend/                 # Web interface files
│   ├── index.html           # Main HTML page
│   ├── style.css            # Modern CSS styling
│   └── script.js            # JavaScript functionality
├── backend/                  # Python API server
│   └── app.py               # Flask API server
├── templates/               # HTML templates (if needed)
├── static/                  # Static assets
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔧 Configuration

### Backend Configuration
The backend server can be configured by modifying `backend/app.py`:

- **Port**: Change `port=5000` to use a different port
- **Host**: Change `host='0.0.0.0'` to restrict access
- **Debug**: Set `debug=False` for production

### Frontend Configuration
Modify `frontend/script.js` to change API settings:

```javascript
// Change API URL if needed
this.apiBaseUrl = 'http://localhost:5000';
```

## 🎨 Customization

### Styling
- Modify `frontend/style.css` to change colors, fonts, and layout
- CSS variables are defined at the top for easy customization
- Dark mode support is included

### Features
- Add new vulnerability types in the backend
- Extend the frontend with additional UI components
- Integrate with external security tools

## 🔒 Security Considerations

### Legal and Ethical Use
⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- **Only test websites you own or have explicit permission to test**
- **Respect robots.txt and rate limiting**
- **Do not use for malicious purposes**
- **Comply with local laws and regulations**

### Best Practices
1. **Get Permission**: Always obtain written permission before testing
2. **Use Test Environments**: Test on staging/development environments first
3. **Monitor Impact**: Be aware of the impact on target systems
4. **Document Everything**: Keep detailed records of testing activities
5. **Report Responsibly**: Report findings through proper channels

## 🚨 Limitations

- Automated scans may not detect all vulnerabilities
- Some vulnerabilities require manual testing
- False positives are possible
- Limited to web application vulnerabilities
- Requires target to be accessible

## 🔍 API Endpoints

### Start Scan
```
POST /api/scan
Content-Type: application/json

{
    "target_url": "https://example.com",
    "max_urls": 20,
    "delay": 1.0
}
```

### Get Scan Status
```
GET /api/scan/{scan_id}
```

### Download Report
```
GET /api/download/{scan_id}/{type}
```
Where `type` is either `pdf` or `json`

### Health Check
```
GET /api/health
```

## 🐛 Troubleshooting

### Common Issues

1. **"Module not found" errors**
   - Run `pip install -r requirements.txt`
   - Ensure you're using Python 3.8+

2. **CORS errors in browser**
   - Make sure the backend is running on the correct port
   - Check that CORS is enabled in the backend

3. **Scan not starting**
   - Check the browser console for JavaScript errors
   - Verify the backend server is running
   - Check network connectivity

4. **Reports not downloading**
   - Ensure the scan completed successfully
   - Check file permissions in the backend directory

### Debug Mode
Enable debug mode for more detailed error messages:

```python
# In backend/app.py
app.run(debug=True)
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users are responsible for ensuring they have proper authorization before using this tool on any target.

## 🆘 Support

For issues, questions, or contributions:

1. Check the troubleshooting section above
2. Review the API documentation
3. Create an issue with detailed information
4. Provide logs and error messages

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally! 