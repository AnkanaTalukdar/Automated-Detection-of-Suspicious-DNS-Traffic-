import math
import collections
import pandas as pd
import tldextract

def calculate_entropy(domain):
    """Measures randomness of a string."""
    if not domain:
        return 0
    probs = [float(v) / len(domain) for v in collections.Counter(domain).values()]
    return -sum(p * math.log(p, 2) for p in probs)

def analyze_traffic(domains):
    """Checks domains for DGA patterns."""
    results = []
    for d in domains:
        # Extract core domain
        ext = tldextract.extract(d)
        name = ext.domain
        if not name: continue
        
        ent = calculate_entropy(name)
        digits = sum(c.isdigit() for c in name)
        
        # Threat Logic
        status = "MALICIOUS (DGA)" if ent > 3.2 or digits > 3 else "Benign"
        
        results.append({
            "Domain": d,
            "Entropy": round(ent, 2),
            "Status": status
        })
    return pd.DataFrame(results)

# --- EXECUTION ---
# Imagine these are logs from your tshark capture
logs = ["google.com", "wikipedia.org","bankofamerica.com", "xy12234lkjndf.net", "vbn9988zz.top"]

print("\n=== DNS THREAT HUNTING REPORT ===")
report = analyze_traffic(logs)
print(report.to_string(index=False))