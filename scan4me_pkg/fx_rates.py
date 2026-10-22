#!/usr/bin/env python3
"""
FX Rates module for Scan4Me — daily cached exchange rates to USD.

Fetches from exchangerate.host (free, no API key required) with 24h TTL cache.
Falls back to static rates if network fails.
"""

import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Optional

# Static fallback rates (used when cache miss + network fails)
_STATIC_FX_TO_USD = {
    "USD": 1.0, "USDC": 1.0, "USDT": 1.0, "DAI": 1.0,
    "EUR": 1.08, "GBP": 1.27, "CHF": 1.13, "AUD": 0.66, "CAD": 0.73,
    "JPY": 0.0067, "CNY": 0.14, "INR": 0.012, "BRL": 0.18, "MXN": 0.05,
    "SGD": 0.74, "HKD": 0.13, "KRW": 0.00075, "TRY": 0.03, "PLN": 0.25,
}

CACHE_TTL = 86400  # 24 hours

def _cache_path() -> Path:
    """Get cache file path."""
    cache_dir = Path(os.environ.get("SCAN4ME_CACHE_DIR", str(Path.home() / ".cache" / "scan4me")))
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "fx_rates.json"


def _fetch_live_rates(base: str = "USD") -> Optional[Dict[str, float]]:
    """Fetch live rates from exchangerate.host."""
    try:
        url = f"https://api.exchangerate.host/latest?base={base}"
        req = urllib.request.Request(url, headers={"User-Agent": "Scan4Me/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.load(resp)
        rates = data.get("rates", {})
        if rates:
            # Ensure base currency is 1.0
            rates[base] = 1.0
            return {k.upper(): float(v) for k, v in rates.items()}
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        pass
    return None


def _load_cached_rates() -> Optional[Dict[str, float]]:
    """Load rates from cache if not expired."""
    path = _cache_path()
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            cached = json.load(f)
        ts = cached.get("ts", 0)
        if time.time() - ts < CACHE_TTL:
            return cached.get("rates")
    except Exception:
        pass
    return None


def _save_cached_rates(rates: Dict[str, float]) -> None:
    """Save rates to cache with timestamp."""
    path = _cache_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(), "rates": rates}, f)
    except Exception:
        pass


def get_fx_rates(force_refresh: bool = False) -> Dict[str, float]:
    """Get FX rates to USD, using cache (24h TTL) or live fetch.

    Args:
        force_refresh: Ignore cache and fetch live.

    Returns:
        Dict mapping currency code -> USD rate.
        Always includes fallback static rates for unknown currencies.
    """
    # Try cache first (unless force_refresh)
    if not force_refresh:
        cached = _load_cached_rates()
        if cached:
            # Merge with static fallback for any missing
            merged = _STATIC_FX_TO_USD.copy()
            merged.update(cached)
            return merged

    # Fetch live
    live = _fetch_live_rates()
    if live:
        _save_cached_rates(live)
        merged = _STATIC_FX_TO_USD.copy()
        merged.update(live)
        return merged

    # Fallback to static
    return _STATIC_FX_TO_USD.copy()


def to_usd(amount, currency: str) -> float:
    """Convert amount to USD using cached/live FX rates.

    Args:
        amount: Numeric amount (or string/None)
        currency: Currency code (e.g., "EUR", "GBP")

    Returns:
        USD amount as float. Unknown currencies return 0.0.
    """
    try:
        value = float(amount or 0)
    except (TypeError, ValueError):
        return 0.0
    if value <= 0:
        return 0.0

    rates = get_fx_rates()
    rate = rates.get(str(currency or "USD").strip().upper())
    return value * rate if rate else 0.0


# Backwards compatibility: expose static rates as module attribute
FX_TO_USD = _STATIC_FX_TO_USD