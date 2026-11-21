"""Northwind Supply: a small, correctly-built serverless store.

This is the app Undertow protects. It is a real target with a real attack
surface (accounts, order IDs, search, reviews, a reset flow, an admin area),
built correctly so that an attacking agent has to work and finds no easy hole.
Nothing here is real: the catalog and customers are generated fake data, the
payment step is a mock, and the app has no route to the internet.
"""
