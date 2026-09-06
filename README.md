\# 🔐 DeepSecure-X



\### AI-Powered Multi-Language Static Code Security Scanner



DeepSecure-X is an AI-powered static code security analysis platform designed to detect security vulnerabilities across multiple programming and web languages.



It automatically detects the submitted programming language, scans the code without executing it, identifies potential vulnerabilities, assigns severity levels, calculates a security score, and provides explanations with remediation recommendations.



\---



\## 🚀 Key Features



\* 🔍 \*\*Multi-Language Static Code Analysis\*\*

\* 🤖 \*\*AI-Powered Security Intelligence\*\*

\* 🛡️ \*\*Vulnerability Detection\*\*

\* ⚠️ \*\*Severity Classification\*\*

\* 📊 \*\*Security Score Calculation\*\*

\* 💡 \*\*Vulnerability Explanation\*\*

\* 🔧 \*\*Remediation Recommendations\*\*

\* 🔐 \*\*User Authentication\*\*

\* 📜 \*\*User-Specific Scan History\*\*

\* 📈 \*\*Security Analytics Dashboard\*\*

\* 🌐 \*\*Automatic Language Detection\*\*

\* 🐳 \*\*Docker Support\*\*

\* ⚡ \*\*FastAPI Backend\*\*

\* ⚛️ \*\*React + Vite Frontend\*\*



\---



\## 🌐 Supported Languages



| Language      | Detection | Static Security Scanner |

| ------------- | --------- | ----------------------- |

| 🐍 Python     | ✅         | ✅                       |

| 🟨 JavaScript | ✅         | ✅                       |

| 🔵 C          | ✅         | ✅                       |

| 🟣 C++        | ✅         | ✅                       |

| ☕ Java        | ✅         | ✅                       |

| 🌐 HTML       | ✅         | ✅                       |

| 🎨 CSS        | ✅         | ✅                       |



> DeepSecure-X performs static analysis only. Submitted code is \*\*not executed\*\* during security scanning.



\---



\## 🏗️ System Architecture



```text

&#x20;                   ┌──────────────────────┐

&#x20;                   │      React UI        │

&#x20;                   │    React + Vite      │

&#x20;                   └──────────┬───────────┘

&#x20;                              │

&#x20;                              ▼

&#x20;                   ┌──────────────────────┐

&#x20;                   │    FastAPI Backend   │

&#x20;                   │   REST API Layer      │

&#x20;                   └──────────┬───────────┘

&#x20;                              │

&#x20;                ┌─────────────┴─────────────┐

&#x20;                │                           │

&#x20;                ▼                           ▼

&#x20;       ┌─────────────────┐        ┌─────────────────┐

&#x20;       │ Language        │        │ Authentication  │

&#x20;       │ Detection       │        │ \& User System   │

&#x20;       └────────┬────────┘        └─────────────────┘

&#x20;                │

&#x20;                ▼

&#x20;       ┌─────────────────────────┐

&#x20;       │ Multi-Language Scanner  │

&#x20;       ├─────────────────────────┤

&#x20;       │ Python                  │

&#x20;       │ JavaScript              │

&#x20;       │ C                       │

&#x20;       │ C++                     │

&#x20;       │ Java                    │

&#x20;       │ HTML                    │

&#x20;       │ CSS                     │

&#x20;       └────────────┬────────────┘

&#x20;                    │

&#x20;                    ▼

&#x20;       ┌─────────────────────────┐

&#x20;       │ Security Analysis       │

&#x20;       │                         │

&#x20;       │ • Vulnerability         │

&#x20;       │ • Severity              │

&#x20;       │ • Security Score        │

&#x20;       │ • Explanation           │

&#x20;       │ • Remediation           │

&#x20;       └────────────┬────────────┘

&#x20;                    │

&#x20;                    ▼

&#x20;       ┌─────────────────────────┐

&#x20;       │ AI Security Intelligence│

&#x20;       └────────────┬────────────┘

&#x20;                    │

&#x20;                    ▼

&#x20;       ┌─────────────────────────┐

&#x20;       │ Scan History \& Analytics│

&#x20;       └─────────────────────────┘

```



\---



\## 🛡️ Security Analysis



DeepSecure-X identifies potentially dangerous coding patterns and security weaknesses using language-specific security rules and analysis pipelines.



\### Severity Levels



| Severity         | Description                                                  |

| ---------------- | ------------------------------------------------------------ |

| 🔴 Critical      | Highly dangerous vulnerability requiring immediate attention |

| 🟠 High          | Significant security risk                                    |

| 🟡 Medium        | Moderate security concern                                    |

| 🔵 Low           | Lower-risk security issue                                    |

| 🟢 Informational | Security-related observation                                 |



\---



\## 📊 Security Scoring



Each scan generates an overall security score based on the vulnerabilities detected.



Example:



```text

Security Score: 70 / 100

Risk Level: Critical

```



The score helps developers quickly understand the overall security posture of their submitted code.



\---



\## 🤖 AI Security Intelligence



DeepSecure-X integrates AI-assisted security analysis to improve the understanding of detected vulnerabilities.



The AI analysis can provide:



\* Vulnerability explanations

\* Security impact

\* Risk interpretation

\* Recommended remediation

\* Secure coding guidance



This allows developers to understand \*\*why a piece of code is vulnerable and how it can be improved\*\*.



\---



\## 🔐 Authentication \& Scan History



DeepSecure-X includes a user authentication system with protected scan history.



Each authenticated user can:



\* Create an account

\* Log in securely

\* Perform security scans

\* View previous scans

\* View scan details

\* Track security scores

\* Access personal analytics



Scan history is isolated between users to prevent unauthorized access to another user's scan data.



\---



\## 📈 Analytics Dashboard



The dashboard provides an overview of security analysis activity.



It can display information such as:



\* Total scans

\* Security scores

\* Vulnerability counts

\* Severity distribution

\* Scan history

\* Security trends



\---



\## 🧪 Example Security Results



The following are example results from the language-specific scanners:



| Language   | Vulnerability  | Severity | Score |

| ---------- | -------------- | -------: | ----: |

| Python     | DANGEROUS\_EVAL | Critical |    70 |

| JavaScript | JS001          |     High |    82 |

| C          | C-001          | Critical |    70 |

| C++        | CPP-002        | Critical |    70 |

| Java       | JAVA-CMD-001   | Critical |    70 |

| HTML       | HTML-XSS-001   |     High |    82 |

| CSS        | CSS-001        |     High |    82 |



\---



\## 🧰 Tech Stack



\### Backend



\* Python

\* FastAPI

\* SQLAlchemy

\* SQLite

\* Pydantic

\* JWT Authentication

\* Uvicorn



\### Frontend



\* React

\* Vite

\* JavaScript

\* Axios

\* React Router

\* Recharts

\* Lucide React



\### AI \& Security



\* AI-assisted security analysis

\* Static code analysis

\* Vulnerability detection

\* Severity classification

\* Security scoring

\* Remediation recommendations



\### DevOps



\* Docker

\* Docker Compose

\* Nginx

\* Git

\* GitHub



\---



\## 📂 Project Structure



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

│   │   ├── \_\_init\_\_.py

│   │   ├── c\_scanner.py

│   │   ├── cpp\_scanner.py

│   │   ├── css\_scanner.py

│   │   ├── html\_scanner.py

│   │   ├── java\_scanner.py

│   │   └── javascript\_scanner.py

│   │

│   ├── services/

│   │   └── ai\_analysis.py

│   │

│   ├── dependencies.py

│   └── main.py

│

├── frontend/

│   ├── src/

│   │   ├── pages/

│   │   ├── components/

│   │   └── styles/

│   │

│   ├── package.json

│   ├── Dockerfile

│   └── nginx.conf

│

├── tests/

│   ├── test\_api.py

│   └── test\_scanner.py

│

├── data/

├── Dockerfile

├── docker-compose.yml

├── requirements.txt

├── .env.example

├── .gitignore

└── README.md

```



\---



\## ⚙️ Installation



\### 1. Clone the Repository



```bash

git clone https://github.com/Pranav1946/DeepSecure-X.git

cd DeepSecure-X

```



\### 2. Create a Virtual Environment



\#### Windows



```powershell

python -m venv .venv

.venv\\Scripts\\activate

```



\#### Linux / macOS



```bash

python3 -m venv .venv

source .venv/bin/activate

```



\### 3. Install Backend Dependencies



```bash

pip install -r requirements.txt

```



\### 4. Configure Environment Variables



Create a `.env` file based on `.env.example`.



```env

ENVIRONMENT=development

DATABASE\_URL=sqlite+aiosqlite:///./deepsecure.db

SECRET\_KEY=your\_secret\_key

OPENAI\_API\_KEY=your\_openai\_api\_key

```



> Never commit the real `.env` file or API keys to GitHub.



\---



\## ▶️ Running the Backend



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



\---



\## ▶️ Running the Frontend



Open a new terminal:



```powershell

cd frontend

npm install

npm run dev

```



Frontend:



```text

http://localhost:5173

```



\---



\## 🐳 Running with Docker



Build and start the application:



```bash

docker compose up --build

```



Stop the application:



```bash

docker compose down

```



\---



\## 🧪 Testing



Run the complete test suite:



```bash

pytest

```



The test suite covers:



\* API functionality

\* Authentication

\* Scanner functionality

\* Multi-language detection

\* Vulnerability detection

\* Security scoring

\* Scan history

\* User isolation



\---



\## 🔍 Supported Detection Flow



DeepSecure-X automatically detects the submitted language.



```text

User submits code

&#x20;       ↓

Language Detection

&#x20;       ↓

Language-specific Scanner

&#x20;       ↓

Vulnerability Detection

&#x20;       ↓

Severity Classification

&#x20;       ↓

Security Score

&#x20;       ↓

AI Security Analysis

&#x20;       ↓

Explanation + Remediation

&#x20;       ↓

Scan Result

```



No manual language selection is required.



\---



\## 🎯 Project Goals



DeepSecure-X aims to provide developers with an accessible security analysis platform that can:



\* Detect common security vulnerabilities early

\* Support multiple programming and web languages

\* Provide understandable security explanations

\* Recommend practical remediation steps

\* Help developers improve secure coding practices

\* Provide a centralized security analysis dashboard



\---



\## 🚀 Future Enhancements



Potential future improvements include:



\* Additional programming language support

\* Advanced AST-based analysis

\* SAST rule expansion

\* CI/CD integration

\* GitHub repository scanning

\* Pull request security analysis

\* Advanced AI vulnerability reasoning

\* Security report export

\* Cloud deployment

\* Enterprise security dashboards



\---



\## 📌 Project Status



\*\*Current Status: Active Development\*\*



DeepSecure-X currently supports static security scanning across \*\*7 languages\*\* with authentication, scan history, security scoring, AI-assisted analysis, analytics, and Docker-based deployment support.



\---



\## 👨‍💻 Author



\### Pranav Balaji



\*\*AI / Machine Learning Enthusiast | Python Developer | Security \& AI Projects\*\*



DeepSecure-X is developed as a practical project combining:



\* Artificial Intelligence

\* Machine Learning

\* Cybersecurity

\* Static Code Analysis

\* Full-Stack Development

\* Backend API Development

\* Secure Software Engineering



\---



\## ⭐ Support



If you find \*\*DeepSecure-X\*\* useful or interesting, consider giving the repository a ⭐ on GitHub.



\*\*Repository:\*\*

https://github.com/Pranav1946/DeepSecure-X



