#!/usr/bin/env python3
"""CLI tool to manage the external API's bearer tokens and enable flag."""

import argparse
import sys


def cmd_create(args):
    from app.api_tokens import create_token

    raw, record = create_token(args.name)
    print(f"Token created: {record['name']} (id={record['id']})")
    print(f"Plaintext (shown once): {raw}")


def cmd_list(_args):
    from app.api_tokens import list_tokens

    tokens = list_tokens()
    if not tokens:
        print("No tokens configured.")
        return
    print(f"{'ID':<38} {'Name':<24} {'Enabled':<8}")
    print("-" * 72)
    for t in tokens:
        print(f"{t['id']:<38} {t['name']:<24} {str(t.get('enabled', True)):<8}")


def cmd_revoke(args):
    from app.api_tokens import revoke_token

    if revoke_token(args.token_id):
        print(f"Token '{args.token_id}' revoked.")
    else:
        print(f"Token '{args.token_id}' not found.", file=sys.stderr)
        sys.exit(1)


def cmd_enable(_args):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    print("External API enabled.")


def cmd_disable(_args):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", False)
    print("External API disabled.")


parser = argparse.ArgumentParser(description="4tlog external API token management")
sub = parser.add_subparsers(dest="command", required=True)

p_create = sub.add_parser("create", help="Create a new bearer token")
p_create.add_argument("name")
p_create.set_defaults(func=cmd_create)

p_list = sub.add_parser("list", help="List all tokens")
p_list.set_defaults(func=cmd_list)

p_revoke = sub.add_parser("revoke", help="Revoke a token by ID")
p_revoke.add_argument("token_id")
p_revoke.set_defaults(func=cmd_revoke)

p_enable = sub.add_parser("enable", help="Enable the external API")
p_enable.set_defaults(func=cmd_enable)

p_disable = sub.add_parser("disable", help="Disable the external API")
p_disable.set_defaults(func=cmd_disable)

if __name__ == "__main__":
    args = parser.parse_args()
    args.func(args)
