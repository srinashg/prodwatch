"""Fake DB layer for the demo."""
import time


def db_query(sql):
    time.sleep(0.05)  # simulate a real round trip
    return {"sql": sql, "rows": []}
