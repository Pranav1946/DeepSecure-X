import json
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.database import Base, get_db
from app.core.security import create_password_reset_token

TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_deepsecure.db"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
)

TestSessionLocal = sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


@pytest.fixture(scope="module", autouse=True)
async def setup_database():
    app.dependency_overrides[get_db] = override_get_db

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    app.dependency_overrides.clear()
    await test_engine.dispose()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as ac:
        yield ac


@pytest.mark.anyio
async def test_root_and_health(client):
    root_resp = await client.get("/")
    assert root_resp.status_code == 200
    assert root_resp.json()["status"] == "secure"

    health_resp = await client.get("/health")
    assert health_resp.status_code == 200
    data = health_resp.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


@pytest.mark.anyio
async def test_register(client):
    username = f"testuser_{uuid.uuid4().hex[:8]}"
    email = f"{username}@example.com"

    response = await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email,
            "password": "TestPassword123!"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["message"] == "User registered successfully"
    assert data["username"] == username
    assert "user_id" in data

    # Duplicate username
    dup_resp = await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"diff_{email}",
            "password": "TestPassword123!"
        }
    )
    assert dup_resp.status_code == 400
    assert "Username already registered" in dup_resp.json()["detail"]

    # Duplicate email
    dup_email_resp = await client.post(
        "/auth/register",
        json={
            "username": f"diff_{username}",
            "email": email,
            "password": "TestPassword123!"
        }
    )
    assert dup_email_resp.status_code == 400
    assert "Email already registered" in dup_email_resp.json()["detail"]


@pytest.mark.anyio
async def test_login_and_me(client):
    username = f"loginuser_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    email = f"{username}@example.com"

    await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password
        }
    )

    # Valid login
    login_response = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert "access_token" in login_data
    assert login_data["token_type"] == "bearer"

    token = login_data["access_token"]

    # Authenticated /me
    me_response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["username"] == username
    assert me_data["email"] == email

    # Invalid login password
    bad_login = await client.post(
        "/auth/login",
        json={"username": username, "password": "WrongPassword!"}
    )
    assert bad_login.status_code == 401


@pytest.mark.anyio
async def test_token_security(client):
    # Test that reset token cannot be used to authenticate as access token
    reset_token = create_password_reset_token(user_id=999)
    resp = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {reset_token}"}
    )
    assert resp.status_code == 401
    assert "Invalid token type" in resp.json()["detail"]

    # Test invalid token string
    invalid_resp = await client.get(
        "/auth/me",
        headers={"Authorization": "Bearer not-a-real-jwt"}
    )
    assert invalid_resp.status_code == 401


@pytest.mark.anyio
async def test_password_reset_flow(client):
    username = f"resetuser_{uuid.uuid4().hex[:8]}"
    email = f"{username}@example.com"
    old_pw = "OldPassword123!"
    new_pw = "NewPassword123!"

    reg_resp = await client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": old_pw}
    )
    assert reg_resp.status_code == 201

    # Forgot password
    forgot_resp = await client.post(
        "/auth/forgot-password",
        json={"email": email}
    )
    assert forgot_resp.status_code == 200
    reset_token = forgot_resp.json().get("reset_token")
    assert reset_token is not None

    # Reset password
    reset_resp = await client.post(
        "/auth/reset-password",
        json={"token": reset_token, "new_password": new_pw}
    )
    assert reset_resp.status_code == 200

    # Login with old password should fail
    fail_login = await client.post(
        "/auth/login",
        json={"username": username, "password": old_pw}
    )
    assert fail_login.status_code == 401

    # Login with new password should succeed
    success_login = await client.post(
        "/auth/login",
        json={"username": username, "password": new_pw}
    )
    assert success_login.status_code == 200


@pytest.mark.anyio
async def test_scanner_python(client):
    username = f"scanner_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password}
    )
    login_response = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    token = login_response.json()["access_token"]

    response = await client.post(
        "/scanner/python",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": 'password = "admin123"\n'}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "python"
    assert data["status"] == "completed"
    assert data["vulnerabilities_found"] >= 1
    assert data["security_score"] < 100
    assert data["risk_level"] == "HIGH"
    assert "scan_id" in data


@pytest.mark.anyio
async def test_scanner_javascript(client):
    username = f"jsscanner_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password}
    )
    login_response = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    token = login_response.json()["access_token"]

    # JS code with eval and innerHTML
    js_code = """
    eval(userInput);
    document.getElementById("output").innerHTML = untrusted;
    const apiKey = "api_key_secret_12345678";
    """
    response = await client.post(
        "/scanner/javascript",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": js_code}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["language"] == "javascript"
    assert data["status"] == "completed"
    assert data["vulnerabilities_found"] >= 2
    assert data["security_score"] < 100


@pytest.mark.anyio
async def test_unsupported_language_rejection(client):
    username = f"unsupported_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password}
    )
    login_resp = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    token = login_resp.json()["access_token"]

    # Attempt to scan Ruby code on unified scan endpoint
    response = await client.post(
        "/scanner/scan",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "code": "def hello; puts 'world'; end",
            "language": "ruby"
        }
    )
    assert response.status_code == 400
    assert "not supported" in response.json()["detail"].lower()
    # Ensure it did NOT return 200 or calculate a 100% score
    assert "security_score" not in response.json()


@pytest.mark.anyio
async def test_scanner_empty_and_invalid_code(client):
    username = f"emptycode_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password}
    )
    login_resp = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    token = login_resp.json()["access_token"]

    # Empty code
    empty_resp = await client.post(
        "/scanner/scan",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": "   ", "language": "python"}
    )
    assert empty_resp.status_code == 400
    assert "cannot be empty" in empty_resp.json()["detail"].lower()

    # Invalid Python syntax
    invalid_py = await client.post(
        "/scanner/python",
        headers={"Authorization": f"Bearer {token}"},
        json={"code": "def func(: syntax error here"}
    )
    assert invalid_py.status_code == 400
    assert "invalid python syntax" in invalid_py.json()["detail"].lower()


@pytest.mark.anyio
async def test_file_upload_validations(client):
    username = f"fileuser_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password}
    )
    login_resp = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    token = login_resp.json()["access_token"]

    # Valid python file
    py_resp = await client.post(
        "/scanner/file",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("test.py", b'password = "secret_pass_123"\n', "text/x-python")}
    )
    assert py_resp.status_code == 200
    assert py_resp.json()["language"] == "python"

    # Valid javascript file
    js_resp = await client.post(
        "/scanner/file",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("app.js", b'eval(userInput);\n', "application/javascript")}
    )
    assert js_resp.status_code == 200
    assert js_resp.json()["language"] == "javascript"

    # Unsupported extension
    bad_ext = await client.post(
        "/scanner/file",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("doc.txt", b'Some plain text content\n', "text/plain")}
    )
    assert bad_ext.status_code == 400
    assert "unsupported file extension" in bad_ext.json()["detail"].lower()

    # Empty file
    empty_file = await client.post(
        "/scanner/file",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("empty.py", b'', "text/x-python")}
    )
    assert empty_file.status_code == 400
    assert "empty" in empty_file.json()["detail"].lower()


@pytest.mark.anyio
async def test_dashboard_analytics_history_details_delete(client):
    username = f"fullflow_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password}
    )
    login_resp = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Perform a scan
    scan_resp = await client.post(
        "/scanner/python",
        headers=headers,
        json={"code": 'import os\nos.system(user_input)\n'}
    )
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    # Dashboard
    dash_resp = await client.get("/scanner/dashboard", headers=headers)
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert dash_data["total_scans"] >= 1
    assert "total_vulnerabilities" in dash_data

    # Analytics
    analytics_resp = await client.get("/scanner/analytics", headers=headers)
    assert analytics_resp.status_code == 200
    analytics_data = analytics_resp.json()
    assert analytics_data["total_scans"] >= 1
    assert "severity_counts" in analytics_data

    # History
    hist_resp = await client.get("/scanner/history", headers=headers)
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()["scans"]) >= 1

    # Scan details
    detail_resp = await client.get(f"/scanner/history/{scan_id}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["scan_id"] == scan_id

    # Delete scan
    del_resp = await client.delete(f"/scanner/history/{scan_id}", headers=headers)
    assert del_resp.status_code == 200

    # Verify deleted
    not_found = await client.get(f"/scanner/history/{scan_id}", headers=headers)
    assert not_found.status_code == 404


@pytest.mark.anyio
async def test_user_specific_scan_numbers_and_history_isolation(client):
    user_a = f"usera_{uuid.uuid4().hex[:8]}"
    user_b = f"userb_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": user_a, "email": f"{user_a}@example.com", "password": password},
    )
    await client.post(
        "/auth/register",
        json={"username": user_b, "email": f"{user_b}@example.com", "password": password},
    )

    a_login = await client.post(
        "/auth/login",
        json={"username": user_a, "password": password},
    )
    a_token = a_login.json()["access_token"]
    b_login = await client.post(
        "/auth/login",
        json={"username": user_b, "password": password},
    )
    b_token = b_login.json()["access_token"]

    a_headers = {"Authorization": f"Bearer {a_token}"}
    b_headers = {"Authorization": f"Bearer {b_token}"}

    for i in range(3):
        scan_resp = await client.post(
            "/scanner/python",
            headers=a_headers,
            json={"code": f"def scan_{i}():\n    return {i}\n"},
        )
        assert scan_resp.status_code == 200

    for i in range(2):
        scan_resp = await client.post(
            "/scanner/python",
            headers=b_headers,
            json={"code": f"def other_scan_{i}():\n    return {i}\n"},
        )
        assert scan_resp.status_code == 200

    a_hist_resp = await client.get("/scanner/history", headers=a_headers)
    b_hist_resp = await client.get("/scanner/history", headers=b_headers)
    assert a_hist_resp.status_code == 200
    assert b_hist_resp.status_code == 200

    a_scans = a_hist_resp.json()["scans"]
    b_scans = b_hist_resp.json()["scans"]

    assert sorted(scan["scan_number"] for scan in a_scans) == [1, 2, 3]
    assert sorted(scan["scan_number"] for scan in b_scans) == [1, 2]
    assert all(scan["scan_number"] not in {4, 5} for scan in a_scans + b_scans)

    for scan in b_scans:
        forbidden = await client.get(f"/scanner/history/{scan['scan_id']}", headers=a_headers)
        assert forbidden.status_code == 404

    for scan in a_scans:
        forbidden = await client.get(f"/scanner/history/{scan['scan_id']}", headers=b_headers)
        assert forbidden.status_code == 404

    assert {scan["scan_id"] for scan in a_scans}.isdisjoint({scan["scan_id"] for scan in b_scans})


@pytest.mark.anyio
async def test_ai_analyze_endpoint(client):
    username = f"aiuser_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password}
    )
    login_resp = await client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Perform a scan
    scan_resp = await client.post(
        "/scanner/python",
        headers=headers,
        json={"code": 'import os\nos.system(user_input)\n'}
    )
    scan_id = scan_resp.json()["scan_id"]

    # Mock OpenAI analysis response
    mock_analysis = {
        "summary": "Critical command injection detected.",
        "overall_risk": "CRITICAL",
        "prioritized_remediation": [
            {
                "priority": 1,
                "rule_id": "COMMAND_INJECTION",
                "explanation": "os.system executes arbitrary shell commands.",
                "remediation_steps": ["Use subprocess.run with argument list."]
            }
        ],
        "secure_practices": ["Avoid executing shell commands with user input."]
    }

    with patch("app.services.ai_analysis.AIAnalysisService.analyze", new_callable=AsyncMock) as mock_analyze:
        mock_analyze.return_value = mock_analysis

        response = await client.post(
            "/ai/analyze",
            headers=headers,
            json={"scan_id": scan_id}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["analysis"]["overall_risk"] == "CRITICAL"
