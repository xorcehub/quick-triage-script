"""MOTW provenance (GENERIC, any kind): parsed Zone.Identifier ADS on Target.
The loader probes the stream (os.walk cannot enumerate NTFS ADS); here we just
report it. Best provenance signal for a download: which site delivered it."""
from ..model import Finding


def run(t):
    m = getattr(t, "motw", None)
    if not m:
        return []
    out = []
    src = m.get("host") or m.get("referrer")
    if src and src.lower() not in ("about:internet", ""):
        extra = f" (referrer: {m['referrer'][:60]})" if m.get("referrer") and m.get("host") else ""
        out.append(Finding("PROV", f"downloaded from: {src[:100]}{extra}"))
    zone = m.get("zone", "")
    if zone.isdigit() and int(zone) >= 3:
        out.append(Finding("PROV?", f"internet-zone download (ZoneId={zone}) "
                                    "- delivered by browser, not authored locally"))
    return out
