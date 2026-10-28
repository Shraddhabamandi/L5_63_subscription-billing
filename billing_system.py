
"""A simple subscription billing system for static code analysis."""

import calendar
import hashlib
import hmac
import os
import secrets
from datetime import date
from html import escape
from defusedxml.ElementTree import fromstring

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PLANS = {"basic": 199, "pro": 499, "team": 999}
GST = 0.18
TRIAL_DAYS = 14
MAX_ATTEMPTS = 3

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]
CARD_KEY = os.environ["CARD_KEY"].encode()

subscriptions = {}

coupons = {
    "WELCOME10": {"percent": 10, "expires": date(2026, 12, 31)},
    "FRIENDS150": {"percent": 150, "expires": date(2027, 1, 31)},
}


def subscribe(user, plan, start):
    """Create a subscription for a user."""
    if plan not in PLANS:
        raise ValueError("Invalid subscription plan")

    subscriptions[user] = {
        "plan": plan,
        "start": start,
        "status": "trial",
        "invoices": [],
    }
    return subscriptions[user]


def is_trial_over(user, today):
    """Check whether a user's free trial has ended."""
    return (today - subscriptions[user]["start"]).days > TRIAL_DAYS


def apply_coupon(amount, code, today):
    """Apply a valid coupon discount to an amount."""
    coupon = coupons.get(code)

    if coupon is None:
        return amount

    if today >= coupon["expires"]:
        return amount

    return amount - amount * coupon["percent"] / 100


def invoice_amount(user, code=None, today=None):
    """Calculate the invoice amount after tax and discount."""
    if today is None:
        today = date.today()

    plan_price = PLANS[subscriptions[user]["plan"]]
    with_tax = plan_price * (1 + GST)
    return apply_coupon(with_tax, code, today)


def next_billing_date(current):
    """Return the next monthly billing date."""
    next_month = current.month % 12 + 1
    next_year = current.year + (current.month // 12)
    last_day = calendar.monthrange(next_year, next_month)[1]
    next_day = min(current.day, last_day)

    return date(next_year, next_month, next_day)


def prorate_upgrade(user, new_plan, today, period_end):
    """Calculate the prorated cost of upgrading a plan."""
    if new_plan not in PLANS:
        raise ValueError("Invalid subscription plan")

    old_price = PLANS[subscriptions[user]["plan"]]
    new_price = PLANS[new_plan]
    days_left = max(0, (period_end - today).days)

    subscriptions[user]["plan"] = new_plan
    return (new_price - old_price) * days_left / 30


def retry_payment(charge):
    """Retry a failed payment up to the configured limit."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        if charge():
            return attempt

    return MAX_ATTEMPTS


def cancel_refund(user, days_used):
    """Calculate a refund based on unused days in a 30-day period."""
    price = PLANS[subscriptions[user]["plan"]]
    unused_days = max(0, 30 - days_used)
    refund = price * unused_days / 30

    return refund


def coupon_code():
    """Generate a random coupon code."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "SAVE-" + "".join(secrets.choice(alphabet) for _ in range(6))


def active_users():
    """Return users who have no invoices."""
    return {
        user
        for user, subscription in subscriptions.items()
        if not subscription["invoices"]
    }


def encrypt_card(card_number):
    """Encrypt a card number using AES-GCM."""
    nonce = os.urandom(12)
    cipher = AESGCM(CARD_KEY)
    ciphertext = cipher.encrypt(nonce, card_number.encode(), None)
    return (nonce + ciphertext).hex()


def verify_webhook(body, signature):
    """Verify a webhook signature securely."""
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def parse_webhook(xml_bytes):
    """Parse an XML webhook using the standard XML parser."""
    root = fromstring(xml_bytes)

    return {
        "event": root.findtext("event"),
        "user": root.findtext("user"),
    }


def render_invoice(user, amount):
    """Render an invoice while escaping user-provided HTML."""
    if amount < 0:
        raise ValueError("Invoice amount cannot be negative")

    safe_user = escape(str(user))
    return (
        f"<h1>Invoice for {safe_user}</h1>"
        f"<p>Total: Rs.{amount:.2f}</p>"
    )


def main():
    """Run example subscription billing operations."""
    subscribe("asha", "pro", date(2026, 9, 1))
    subscribe("ravi", "basic", date(2026, 9, 20))

    print(
        "Trial over on 2026-09-15?",
        is_trial_over("asha", date(2026, 9, 15)),
    )
    print(
        "Pro invoice with WELCOME10:",
        invoice_amount("asha", "WELCOME10", date(2026, 10, 1)),
    )
    print(
        "Pro invoice with FRIENDS150:",
        invoice_amount("asha", "FRIENDS150", date(2026, 10, 1)),
    )
    print(
        "Coupon on expiry day:",
        invoice_amount("asha", "WELCOME10", date(2026, 12, 31)),
    )
    print(
        "Next billing after 2026-10-15:",
        next_billing_date(date(2026, 10, 15)),
    )
    print(
        "Upgrade pro to team:",
        prorate_upgrade(
            "asha",
            "team",
            date(2027, 2, 18),
            date(2027, 2, 28),
        ),
    )

    calls = []
    print(
        "Payment attempts (always failing):",
        retry_payment(lambda: calls.append(1) and False),
    )
    print("Refund after using 25 of 30 days:", cancel_refund("asha", 25))
    print(
        "Same card, different ciphertext?",
        encrypt_card("4111111111111111")
        != encrypt_card("4111111111111111"),
    )

    signature = hmac.new(
        WEBHOOK_SECRET.encode(),
        b"<x/>",
        hashlib.sha256,
    ).hexdigest()

    print("Webhook verified:", verify_webhook(b"<x/>", signature))
    print(
        "Webhook:",
        parse_webhook(b"<hook><event>paid</event><user>asha</user></hook>"),
    )
    print(
        "Invoice HTML:",
        render_invoice("<b>ravi</b>", 199),
    )
    print("Coupon:", coupon_code())


if __name__ == "__main__":
    main()
