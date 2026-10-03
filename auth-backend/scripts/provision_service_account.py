#!/usr/bin/env python3
"""Create (or rotate the secret of) a service account -- the production
path for service-to-service authentication, mirroring Core's own
scripts/provision_*_service_account.py pattern in shape (print the secret
once, support idempotent re-runs, a separate --rotate-secret mode), but
against Blumax Auth's OWN ServiceAccount model (app/models/
service_account.py) -- see that model's docstring for why a service
account here is NOT a "shadow user" the way Core's are.

Usage:
    python scripts/provision_service_account.py create \\
        --name blumax-labs --destination-app labs

    python scripts/provision_service_account.py create \\
        --name blumax-doctor-portal-sso --may-mint-on-behalf \\
        --allowed-mint-destinations labs,pharmacy

    python scripts/provision_service_account.py create \\
        --name blumax-labs-identity-admin --may-manage-identities

    python scripts/provision_service_account.py rotate-secret --name blumax-labs

Never run against a production database without the operator explicitly
intending to -- this script has no "which environment am I pointed at"
guard of its own; DATABASE_URL (from the environment/.env) decides that,
same as every other script in this service.
"""
from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
import uuid

from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models.service_account import ServiceAccount


async def create(args: argparse.Namespace) -> None:
    async with AsyncSessionLocal() as db:
        existing = await db.execute(select(ServiceAccount).where(ServiceAccount.name == args.name))
        if existing.scalar_one_or_none() is not None:
            print(f"service account {args.name!r} already exists -- use rotate-secret instead", file=sys.stderr)
            raise SystemExit(1)

        client_secret = secrets.token_urlsafe(32)
        account = ServiceAccount(
            id=uuid.uuid4(),
            name=args.name,
            client_id=f"{args.name}-{uuid.uuid4().hex[:12]}",
            client_secret_hash=hash_password(client_secret),
            is_active=True,
            destination_app=args.destination_app,
            may_mint_on_behalf=args.may_mint_on_behalf,
            allowed_mint_destinations=args.allowed_mint_destinations.split(",") if args.allowed_mint_destinations else None,
            may_manage_identities=args.may_manage_identities,
        )
        db.add(account)
        await db.commit()
        await db.refresh(account)

        print(f"created service account: {account.name}")
        print(f"  client_id:     {account.client_id}")
        print(f"  client_secret: {client_secret}   (shown once -- store it now)")
        print(f"  destination_app: {account.destination_app!r}")
        print(f"  may_mint_on_behalf: {account.may_mint_on_behalf}")
        print(f"  allowed_mint_destinations: {account.allowed_mint_destinations!r}")
        print(f"  may_manage_identities: {account.may_manage_identities}")


async def rotate_secret(args: argparse.Namespace) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ServiceAccount).where(ServiceAccount.name == args.name))
        account = result.scalar_one_or_none()
        if account is None:
            print(f"no such service account: {args.name!r}", file=sys.stderr)
            raise SystemExit(1)

        client_secret = secrets.token_urlsafe(32)
        account.client_secret_hash = hash_password(client_secret)
        await db.commit()

        print(f"rotated secret for: {account.name}")
        print(f"  client_id:     {account.client_id}   (unchanged)")
        print(f"  client_secret: {client_secret}   (shown once -- store it now)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    create_p = sub.add_parser("create")
    create_p.add_argument("--name", required=True)
    create_p.add_argument("--destination-app", default=None, help="which app this account may EXCHANGE inbound SSO codes for")
    create_p.add_argument("--may-mint-on-behalf", action="store_true")
    create_p.add_argument("--allowed-mint-destinations", default=None, help="comma-separated, only used with --may-mint-on-behalf")
    create_p.add_argument("--may-manage-identities", action="store_true")

    rotate_p = sub.add_parser("rotate-secret")
    rotate_p.add_argument("--name", required=True)

    args = parser.parse_args()
    if args.command == "create":
        asyncio.run(create(args))
    elif args.command == "rotate-secret":
        asyncio.run(rotate_secret(args))


if __name__ == "__main__":
    main()
