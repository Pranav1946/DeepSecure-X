import asyncio
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.scan import Scan


async def check():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan))
        scans = result.scalars().all()

        print("TOTAL SCANS:", len(scans))

        for scan in scans:
            print("\n-------------------------")
            print("SCAN ID:", scan.id)
            print("USER ID:", scan.user_id)
            print("LANGUAGE:", scan.language)
            print("STATUS:", scan.status)
            print("VULNERABILITIES:", scan.vulnerabilities_found)
            print("RESULTS:", scan.results)


asyncio.run(check())