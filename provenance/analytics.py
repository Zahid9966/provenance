import math
from datetime import datetime, timedelta

def rows(conn, sql, *a): return [dict(r) for r in conn.execute(sql, a)]

def overview(conn):
    k = rows(conn, """SELECT count(CASE WHEN status<>'CANCELLED' THEN 1 END) orders, sum(CASE WHEN status<>'CANCELLED' THEN total END) gmv,
        sum(refunded) refunds, sum(fees) fees, sum(leak) leakage, sum(CASE WHEN recon_state='EXCEPTION' THEN 1 ELSE 0 END) exceptions,
        sum(CASE WHEN status<>'CANCELLED' THEN total-cogs-fees-refunded END) contribution FROM gold_order_fin""")[0]
    return {"kpis": k, "by_channel": channel_summary(conn), "leak_by_reason": rows(conn, """SELECT recon_reason reason, count(*) n, sum(abs(variance)) leak_paise FROM gold_order_fin
        WHERE recon_state='EXCEPTION' GROUP BY 1 ORDER BY 3 DESC"""), "daily": daily(conn)}

def channel_summary(conn):
    return rows(conn, """SELECT channel, count(CASE WHEN status<>'CANCELLED' THEN 1 END) orders, sum(CASE WHEN status<>'CANCELLED' THEN total END) gmv,
        sum(fees) fees, sum(refunded) refunds, sum(leak) leakage, sum(CASE WHEN status<>'CANCELLED' THEN total-cogs-fees-refunded END) contribution,
        round(100.0*sum(CASE WHEN status='RETURNED' THEN 1 ELSE 0 END)/count(*),1) return_pct,
        round(100.0*(SELECT count(*) FROM (SELECT customer_token FROM gold_order_fin g2 WHERE g2.channel=g.channel GROUP BY customer_token HAVING count(*)>1) rep)
              /(SELECT count(DISTINCT customer_token) FROM gold_order_fin g3 WHERE g3.channel=g.channel),1) repeat_pct
        FROM gold_order_fin g GROUP BY channel ORDER BY gmv DESC""")

def daily(conn):
    return rows(conn, """SELECT day, channel, sum(CASE WHEN status<>'CANCELLED' THEN total END) gmv, count(*) orders, 100.0*sum(CASE WHEN status='RETURNED' THEN 1 ELSE 0 END)/count(*) return_pct
                         FROM gold_order_fin GROUP BY day, channel ORDER BY day""")

def _pois_cdf(k, mu):
    t = term = math.exp(-mu)
    for i in range(1, k + 1): term *= mu / i; t += term
    return min(t, 1.0)

def _binom_sf(k, n, p):  # P(X >= k)
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k, n + 1))

def anomalies(conn, window=28, alpha=1e-3):
    """Exact tail tests on sparse daily series (robust z-scores misbehave at low counts).
    Volume: Poisson tail vs. same day-type (weekday/weekend) mean over the trailing window. Returns: binomial tail vs. trailing return rate."""
    out, series = [], {}
    for r in daily(conn): series.setdefault(r["channel"], []).append(r)
    for ch, s in series.items():
        for i in range(window, len(s)):
            day = datetime.strptime(s[i]["day"], "%Y-%m-%d"); wk = day.weekday() >= 5
            hist = [x for x in s[i - window:i] if (datetime.strptime(x["day"], "%Y-%m-%d").weekday() >= 5) == wk]
            if len(hist) < 3: continue
            mu = sum(x["orders"] for x in hist) / len(hist); k = s[i]["orders"]
            if mu >= 4:
                p_lo, p_hi = _pois_cdf(k, mu), 1 - _pois_cdf(k - 1, mu)
                if p_lo < alpha: out.append({"channel": ch, "day": s[i]["day"], "type": "volume_drop", "observed": k, "expected": round(mu, 1), "p_value": p_lo})
                elif p_hi < alpha: out.append({"channel": ch, "day": s[i]["day"], "type": "volume_surge", "observed": k, "expected": round(mu, 1), "p_value": p_hi})
            rate_hist = sum(x["return_pct"] * x["orders"] / 100 for x in s[i - window:i]) / max(1, sum(x["orders"] for x in s[i - window:i]))
            ret = round(s[i]["return_pct"] * k / 100)
            if k >= 5 and ret >= 3:
                p_hi = _binom_sf(ret, k, max(rate_hist, 0.02))
                if p_hi < alpha: out.append({"channel": ch, "day": s[i]["day"], "type": "return_spike", "observed": f"{ret}/{k}", "expected": f"{100*rate_hist:.1f}%", "p_value": p_hi})
    return sorted(out, key=lambda a: a["p_value"])

def exceptions(conn, state="EXCEPTION", channel=None, reason=None, limit=200):
    q, a = "SELECT * FROM gold_order_fin WHERE recon_state=?", [state]
    if channel: q += " AND channel=?"; a.append(channel)
    if reason: q += " AND recon_reason=?"; a.append(reason)
    return rows(conn, q + " ORDER BY leak DESC, day DESC LIMIT ?", *a, min(limit, 500))

def recall_exposure(conn, lot_id):
    """Forward trace from a supplier lot to every order, channel and (tokenized) customer that received it."""
    lot = rows(conn, "SELECT * FROM silver_lots WHERE lot_id=?", lot_id)
    if not lot: return None
    items = rows(conn, """SELECT o.order_id, o.channel, o.status, o.customer_token, i.qty, i.qty*i.unit_price rev FROM silver_items i JOIN silver_orders o USING(order_id)
                          WHERE i.lot_id=? AND o.status<>'CANCELLED'""", lot_id)
    by_ch = {}
    for i in items: d = by_ch.setdefault(i["channel"], {"orders": 0, "units": 0, "revenue": 0}); d["orders"] += 1; d["units"] += i["qty"]; d["revenue"] += i["rev"]
    return {"lot": lot[0], "orders": len({i["order_id"] for i in items}), "customers": len({i["customer_token"] for i in items}), "units": sum(i["qty"] for i in items),
            "revenue_paise": sum(i["rev"] for i in items), "by_channel": by_ch,
            "note": "Customer counts are tokens; notification goes through the owning channel (marketplaces notify their own buyers)."}
