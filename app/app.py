from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

# ==========================
# Load models
# ==========================
iso_model = joblib.load("model/iso_forest_nids.pkl")
rf_model  = joblib.load("model/ai_nids_random_forest.pkl")

# ==========================
# Feature order (STRICT)
# ==========================
FEATURE_ORDER = [
    "packet_count",
    "total_bytes",
    "duration",
    "protocol",
    "tcp_syn_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "alert_count",
    "session_anomaly_count"
]

# ==========================
# Thresholds
# ==========================
ISO_THRESHOLD = 0.04156497807855598
RF_THRESHOLD  = 0.08644691229094409

# ==========================
# Protocol mapping (IANA)
# ==========================
PROTOCOL_MAP = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "DNS": 17,
    "QUIC": 17,
    "SSL": 6,
    "TLS": 6,
    "TLSV1.2": 6,
    "TLSV1.3": 6,
    "HTTPS": 6,
    "HTTP": 6,
}

REVERSE_PROTOCOL_MAP = {v: k for k, v in PROTOCOL_MAP.items()}


def protocol_to_number(proto) -> int:
    if proto is None:
        return 0

    if isinstance(proto, (int, float)):
        return int(proto)

    proto = str(proto).upper().replace(".", "").replace(" ", "")
    return PROTOCOL_MAP.get(proto, 0)


def protocol_to_name(proto_num: int) -> str:
    return REVERSE_PROTOCOL_MAP.get(int(proto_num), "UNKNOWN")


def get_float(data, key):
    try:
        return float(data.get(key, 0))
    except (TypeError, ValueError):
        return 0.0


# ==========================
# Routes
# ==========================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True, silent=True)

    print("RAW REQUEST DATA:", data)

    if not data:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    # ---- Normalize protocol ONCE ----
    protocol_num = protocol_to_number(data.get("protocol"))

    # ---- Build feature dataframe ----
    features_df = pd.DataFrame([{
        "packet_count": get_float(data, "packet_count"),
        "total_bytes": get_float(data, "total_bytes"),
        "duration": get_float(data, "duration"),
        "protocol": protocol_num,
        "tcp_syn_count": get_float(data, "tcp_syn_count"),
        "tcp_fin_count": get_float(data, "tcp_fin_count"),
        "tcp_rst_count": get_float(data, "tcp_rst_count"),
        "alert_count": get_float(data, "alert_count"),
        "session_anomaly_count": get_float(data, "session_anomaly_count"),
    }], columns=FEATURE_ORDER)

    # ==========================
    # Isolation Forest
    # ==========================
    iso_score = -iso_model.decision_function(features_df)[0]
    iso_verdict = "Attack" if iso_score >= ISO_THRESHOLD else "Benign"

    # ==========================
    # Random Forest
    # ==========================
    rf_prob = rf_model.predict_proba(features_df)[0][1]
    rf_verdict = "Attack" if rf_prob >= RF_THRESHOLD else "Benign"

    # ==========================
    # Hybrid SOC Logic
    # ==========================
    if iso_verdict == "Attack" and rf_verdict == "Attack":
        final_verdict = "Attack"
    elif iso_verdict == "Attack":
        final_verdict = "Suspicious"
    else:
        final_verdict = "Benign"

    return jsonify({
        "final_verdict": final_verdict,
        "protocol": {
            "number": protocol_num,
            "name": protocol_to_name(protocol_num)
        },
        "isolation_forest": {
            "verdict": iso_verdict,
            "anomaly_score": round(float(iso_score), 4),
            "threshold": ISO_THRESHOLD
        },
        "random_forest": {
            "verdict": rf_verdict,
            "probability": round(float(rf_prob), 4),
            "threshold": RF_THRESHOLD
        }
    })


if __name__ == "__main__":
    app.run(debug=True)