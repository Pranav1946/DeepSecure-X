import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.database import Base, get_db


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
async def test_register(client):
    username = f"testuser_{uuid.uuid4().hex[:8]}"

    response = await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "TestPassword123!"
        }
    )

    assert response.status_code == 201

    data = response.json()

    assert data["message"] == "User registered successfully"
    assert data["username"] == username
    assert "user_id" in data


@pytest.mark.anyio
async def test_login_and_me(client):
    username = f"loginuser_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    register_response = await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )

    assert register_response.status_code == 201

    login_response = await client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password
        }
    )

    assert login_response.status_code == 200

    login_data = login_response.json()

    assert "access_token" in login_data
    assert login_data["token_type"] == "bearer"

    token = login_data["access_token"]

    me_response = await client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert me_response.status_code == 200

    me_data = me_response.json()

    assert me_data["username"] == username
    assert me_data["email"] == f"{username}@example.com"


@pytest.mark.anyio
async def test_scanner_python(client):
    username = f"scanner_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )

    login_response = await client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password
        }
    )

    token = login_response.json()["access_token"]

    response = await client.post(
        "/scanner/python",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "code": """
password = "admin123"
"""
        }
    )

    assert response.status_code == 200

    data = response.json()

    print("\nSCANNER API RESPONSE:", data)
    assert data["language"] == "python"
    assert data["status"] == "completed"
    assert data["vulnerabilities_found"] >= 1
    assert data["security_score"] < 100
    assert data["risk_level"] == "HIGH"
    assert "scan_id" in data


@pytest.mark.anyio
async def test_dashboard(client):
    username = f"dashboard_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )

    login_response = await client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password
        }
    )

    token = login_response.json()["access_token"]

    response = await client.get(
        "/scanner/dashboard",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "total_scans" in data
    assert "total_vulnerabilities" in data
    assert "severity_counts" in data
    assert "average_security_score" in data
    assert "latest_risk_level" in data


@pytest.mark.anyio
async def test_analytics(client):
    username = f"analytics_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )

    login_response = await client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password
        }
    )

    token = login_response.json()["access_token"]

    response = await client.get(
        "/scanner/analytics",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "total_scans" in data
    assert "total_vulnerabilities" in data
    assert "severity_counts" in data
    assert "risk_distribution" in data
    assert "top_vulnerabilities" in data
    assert "scan_activity" in data


@pytest.mark.anyio
async def test_scan_history(client):
    username = f"history_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"

    await client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )

    login_response = await client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password
        }
    )

    token = login_response.json()["access_token"]

    response = await client.get(
        "/scanner/history",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "scans" in data
    assert "total_scans" in data