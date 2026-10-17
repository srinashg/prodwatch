"""Demo order service — INTENTIONALLY FLAWED for the ProdWatch demo.

Every flaw below is something ProdWatch should catch. Do not use as a reference.
"""
import asyncio
import time

import requests

from db import db_query

API_KEY = "sk-live-9f8e7d6c5b4a312"          # REL002: hardcoded secret
DB_URL = "postgres://admin:s3cret123@db:5432/shop"  # REL002: password in code
UPSTREAM = "https://api.example.com"


def get_order(order_id):
    resp = requests.get(f"{UPSTREAM}/orders/{order_id}")  # PY001: no timeout
    return resp.json()


def get_all_orders(order_ids):
    results = []
    for oid in order_ids:
        # PY002: query inside a loop (N+1)
        results.append(db_query(f"SELECT * FROM orders WHERE id = {oid}"))
    return results


async def refresh_prices(order_ids):
    time.sleep(2)  # PY003: blocking the event loop
    for oid in order_ids:
        requests.post(f"{UPSTREAM}/prices/refresh",  # PY001: no timeout
                      json={"id": oid})
    return True


def charge_card(order):
    try:
        resp = requests.post(f"{UPSTREAM}/pay", json=order, timeout=5)
        return resp.json()
    except:  # REL001: bare except, swallows everything
        pass


def run():
    print("starting order service...")  # GEN001: print instead of logging
    orders = get_all_orders([1, 2, 3])
    print(f"loaded {len(orders)} orders")  # GEN001


if __name__ == "__main__":
    run()
