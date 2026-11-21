"""Deterministic fake catalog and customers. Generated in code (no model calls,
no network), so a fresh table seeds identically every time. All invented."""
from __future__ import annotations

import random

from .store import hash_password

CATEGORIES = {
    "Workshop": ["Cordless Drill", "Impact Driver", "Orbital Sander", "Bench Vise", "Socket Set",
                 "Torque Wrench", "Heat Gun", "Angle Grinder", "Nail Gun", "Rotary Tool"],
    "Outdoor": ["Camp Stove", "Dry Bag", "Trekking Poles", "Headlamp", "Water Filter",
                "Hammock", "Folding Saw", "Tarp Shelter", "Fire Steel", "Cooler Box"],
    "Garden": ["Pruning Shears", "Garden Hose", "Wheelbarrow", "Soil Meter", "Seed Trays",
               "Loppers", "Watering Can", "Hedge Trimmer", "Compost Bin", "Leaf Blower"],
    "Kitchen": ["Chef Knife", "Cast Pan", "Stock Pot", "Mixing Bowls", "Kettle",
                "Cutting Board", "Peppermill", "Measuring Set", "Dutch Oven", "Whisk Set"],
    "Electrical": ["Multimeter", "Cable Reel", "Wire Strippers", "Surge Strip", "Work Light",
                   "Solder Iron", "Volt Tester", "Junction Box", "Terminal Kit", "Fuse Pack"],
}
BRANDS = ["Northwind", "Tailspin", "Fabrikam", "Contoso", "Litware", "Proseware", "Wingtip"]
ADJ = ["Pro", "Compact", "Heavy-Duty", "Classic", "Max", "Lite", "Field", "Shop", "Trade", "Core"]
FIRST = ["Jordan", "Riley", "Casey", "Morgan", "Avery", "Quinn", "Parker", "Reese", "Devon", "Harper",
         "Emerson", "Rowan", "Sawyer", "Blake", "Hayden", "Marlowe", "Tatum", "Collins", "Ellis", "Kai"]
LAST = ["Ortiz", "Chen", "Patel", "Nguyen", "Okafor", "Rossi", "Haddad", "Kowalski", "Sorensen", "Vance",
        "Delgado", "Abbott", "Ramsey", "Lindqvist", "Ibrahim", "Mercer", "Fontaine", "Underwood", "Yamada", "Pike"]


def catalog(seed: int = 7) -> list[dict]:
    r = random.Random(seed)
    out, n = [], 0
    for cat, names in CATEGORIES.items():
        for base in names:
            n += 1
            brand, adj = r.choice(BRANDS), r.choice(ADJ)
            price = r.choice([1299, 1999, 2499, 3499, 4999, 6999, 8999, 12999, 15999, 24999])
            out.append({
                "pk": "PRODUCT", "sk": f"prd_{n:04d}",
                "name": f"{brand} {adj} {base}", "category": cat,
                "price": price, "stock": r.randint(0, 220),
                "sku": f"{cat[:3].upper()}-{n:04d}",
                "blurb": f"The {brand} {adj} {base.lower()} for {cat.lower()} work. "
                         f"{r.choice(['Two-year', 'Lifetime', 'Five-year'])} warranty.",
            })
    return out


def customers(seed: int = 7, n: int = 60) -> list[dict]:
    r = random.Random(seed + 1)
    out, used = [], set()
    while len(out) < n:
        f, l = r.choice(FIRST), r.choice(LAST)
        email = f"{f}.{l}{r.randint(1, 99)}@example.com".lower()
        if email in used:
            continue
        used.add(email)
        out.append({"pk": "USER", "sk": email, "name": f"{f} {l}", "role": "customer",
                    "pw": hash_password(f"{l}-{r.randint(1000, 9999)}!pw"), "created": 1_700_000_000 + len(out) * 3600})
    return out


def admin(email: str, password: str) -> dict:
    return {"pk": "USER", "sk": email.lower(), "name": "Store Admin", "role": "admin",
            "pw": hash_password(password), "created": 1_700_000_000}


def all_items(admin_email: str, admin_password: str) -> list[dict]:
    return [*catalog(), *customers(), admin(admin_email, admin_password)]
