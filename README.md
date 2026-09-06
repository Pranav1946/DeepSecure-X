# 🔐 DeepSecure-X

### AI-Powered Multi-Language Static Code Security Scanner

DeepSecure-X is an AI-powered static code security analysis platform designed to detect security vulnerabilities across multiple programming and web languages without executing the submitted code.

It combines **rule-based static analysis, AI-powered security intelligence, vulnerability classification, security scoring, and remediation recommendations** into a unified security scanning platform.

---

## 🚀 Key Features

* 🔍 **Multi-language static security scanning**
* 🤖 **AI-powered security analysis**
* 🛡️ **Vulnerability detection and classification**
* ⚠️ **Severity-based risk assessment**
* 📊 **Security score generation**
* 💡 **Vulnerability explanations**
* 🔧 **Remediation recommendations**
* 🔐 **User authentication and protected scan history**
* 📈 **Security analytics dashboard**
* 🧾 **Detailed scan results**
* 🌐 **Automatic programming-language detection**
* 🐳 **Docker support**
* ⚡ **FastAPI-based backend**
* ⚛️ **React + Vite frontend**

---

## 🌐 Supported Languages

DeepSecure-X currently supports **7 languages**:

| Language      | Scanner                     |
| ------------- | --------------------------- |
| 🐍 Python     | Python Security Scanner     |
| 🟨 JavaScript | JavaScript Security Scanner |
| 🇨 C          | C Security Scanner          |
| ⚙️ C++        | C++ Security Scanner        |
| ☕ Java        | Java Security Scanner       |
| 🌐 HTML       | HTML Security Scanner       |
| 🎨 CSS        | CSS Security Scanner        |

The platform automatically detects the submitted language and routes the code to the appropriate security scanner.

---

## 🧠 How DeepSecure-X Works

```text
                 ┌──────────────────────┐
                 │      User / Client   │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │    React Frontend    │
                 │      + Vite          │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │     FastAPI API      │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Language Detection   │
                 └──────────┬───────────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
        ┌─────────┐    ┌─────────┐    ┌─────────┐
        │ Python  │    │   Web   │    │ C/C++/  │
        │ Scanner │    │Scanner  │    │  Java   │
        └────┬────┘    └────┬────┘    └────┬────┘
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                 ┌──────────────────────┐
                 │ Vulnerability        │
                 │ Detection & Analysis │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ AI Security          │
                 │ Intelligence         │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Severity + Score +   │
                 │ Explanation + Fix    │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Dashboard / Results  │
                 └──────────────────────┘
```

---

## 🔐 Security Analysis

DeepSecure-X performs **static analysis**, meaning submitted source code is analyzed without executing it.

The scanners identify potentially dangerous patterns such as:

* Dangerous function usage
* Command injection risks
* Cross-Site Scripting (XSS)
* Unsafe code execution
* Insecure input handling
* Security-sensitive coding patterns
* Language-specific vulnerabilities

Each detected issue can be classified according to its security impact.

### Severity Levels

```text
CRITICAL
HIGH
MEDIUM
LOW
```

---

## 📊 Security Scoring

DeepSecure-X generates a security score based on detected vulnerabilities.

Example:

```text
Security Score: 70 / 100
Risk Level: CRITICAL

Detected Vulnerability:
DANGEROUS_EVAL

Severity:
CRITICAL
```

The dashboard provides users with a quick overview of the security posture of their submitted code.

---

## 🤖 AI Security Intelligence

DeepSecure-X integrates AI-based analysis to enhance the security scanning workflow.

The AI analysis layer can provide:

* Vulnerability explanations
* Security context
* Risk interpretation
* Remediation guidance
* Developer-friendly recommendations

This helps developers understand **why a piece of code is potentially insecure and how it can be improved**.

---

## 🔐 Authentication & Scan History

DeepSecure-X includes authenticated user workflows.

Users can:

* Register an account
* Log in securely
* Reset passwords
* Submit security scans
* View previous scans
* View detailed scan results
* Access security analytics

Scan history is isolated between users so that one user cannot access another user's scans.

---

## 🖥️ Frontend

The frontend is built using:

* React
* Vite
* React Router
* Axios
* Recharts
* Lucide React
* CSS

### Frontend Pages

```text
Login
Register
Forgot Password
Reset Password
Dashboard
Scanner
Scan Details
Analytics
```

---

## ⚙️ Backend

The backend is built using **FastAPI** and provides APIs for:

* Authentication
* User management
* Code scanning
* Scan history
* Scan details
* AI security analysis
* Security analytics

---

## 🛠️ Technology Stack

### Backend

```text
Python
FastAPI
SQLAlchemy
SQLite / PostgreSQL
Pydantic
JWT Authentication
OpenAI API
```

### Frontend

```text
React
Vite
JavaScript
Axios
React Router
Recharts
Lucide React
CSS
```

### DevOps

```text
Docker
Docker Compose
Nginx
Git
GitHub
```

---

## 📂 Project Structure

```text
DeepSecure-X/
│
├── app/
│   ├── api/
│   │   ├── ai.py
│   │   ├── auth.py
│   │   └── scanner.py
│   │
│   ├── core/
│   │   ├── database.py
│   │   └── security.py
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── c_scanner.py
│   │   ├── cpp_scanner.py
│   │   ├── css_scanner.py
│   │   ├── html_scanner.py
│   │   ├── java_scanner.py
│   │   ├── javascript_scanner.py
│   │   └── ...
│   │
│   ├── services/
│   │   └── ai_analysis.py
│   │
│   ├── schemas/
│   ├── dependencies.py
│   └── main.py
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── App.jsx
│   │   └── ...
│   │
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── .env.example
│
├── tests/
│   ├── test_api.py
│   └── test_scanner.py
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## ⚙️ Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/Pranav1946/DeepSecure-X.git
cd DeepSecure-X
```

### 2. Create a Python virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install backend dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file from the example:

```powershell
Copy-Item .env.example .env
```

Configure your environment variables:

```env
ENVIRONMENT=development
DATABASE_URL=sqlite+aiosqlite:///./deepsecure.db
SECRET_KEY=your_secure_secret_key
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o-mini
CORS_ORIGINS=http://localhost:5173
```

> **Never commit your `.env` file or API keys to GitHub.**

---

## ▶️ Run the Backend

Start the FastAPI server:

```bash
uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

---

## ▶️ Run the Frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

Configure the frontend API URL using:

```env
VITE_API_URL=http://127.0.0.1:8000
```

---

## 🐳 Docker

DeepSecure-X also includes Docker configuration for containerized execution.

Build and start the services:

```bash
docker compose up --build
```

Stop the services:

```bash
docker compose down
```

---

## 🧪 Testing

Run the backend test suite:

```bash
pytest
```

The project includes API and scanner tests covering:

* Authentication APIs
* Scanner APIs
* Language detection
* Vulnerability detection
* Security scoring
* Multi-language scanning workflows

---

## 📈 Example Security Results

Example vulnerability detection:

| Language   | Vulnerability  | Severity | Score |
| ---------- | -------------- | -------: | ----: |
| Python     | DANGEROUS_EVAL | Critical |    70 |
| JavaScript | JS001          |     High |    82 |
| C          | C-001          | Critical |    70 |
| C++        | CPP-002        | Critical |    70 |
| Java       | JAVA-CMD-001   | Critical |    70 |
| HTML       | HTML-XSS-001   |     High |    82 |
| CSS        | CSS-001        |     High |    82 |

---

## 🎯 Project Goals

DeepSecure-X aims to make source-code security analysis more accessible to developers by providing a single platform for analyzing multiple programming and web languages.

The project focuses on combining:

```text
Static Analysis
      +
AI Security Intelligence
      +
Vulnerability Classification
      +
Security Scoring
      +
Remediation Guidance
```

---

## 🔮 Future Enhancements

* 🌐 Cloud deployment
* 🗄️ Production PostgreSQL database
* 📄 PDF security reports
* 🔄 CI/CD security scanning
* 🔌 GitHub repository integration
* 🧩 Additional programming languages
* 🧠 Advanced AI vulnerability reasoning
* 📊 Advanced security analytics
* 🔔 Real-time security notifications

---

## 👨‍💻 Author

**Pranav Balaji**

AI / Machine Learning Enthusiast | Python Developer | Security & AI Projects

### Project

**DeepSecure-X — AI-Powered Multi-Language Static Code Security Scanner**

---

## ⭐ Support

If you find DeepSecure-X useful or interesting, consider giving the repository a ⭐ on GitHub.

**Repository:**
https://github.com/Pranav1946/DeepSecure-X
