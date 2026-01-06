async function predict() {
    const data = {
        packet_count: Number(document.getElementById("packet_count").value),
        total_bytes: Number(document.getElementById("total_bytes").value),
        duration: Number(document.getElementById("duration").value),
        protocol: Number(document.getElementById("protocol").value),
        tcp_syn_count: Number(document.getElementById("tcp_syn_count").value),
        tcp_fin_count: Number(document.getElementById("tcp_fin_count").value),
        tcp_rst_count: Number(document.getElementById("tcp_rst_count").value),
        alert_count: Number(document.getElementById("alert_count").value),
        session_anomaly_count: Number(document.getElementById("session_anomaly_count").value)
    };

    console.log("Sending data:", data);

    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();
        console.log("Received result:", result);

        // Update status
        document.getElementById("analysis-status").innerText =
            "Analysis completed. Result is displayed below.";

        // Update inline result div
        document.getElementById("analysis-output").innerHTML = `
          <strong>Final Verdict:</strong> ${result.final_verdict}<br>
          <strong>Isolation Forest:</strong> ${result.isolation_forest.verdict} 
          (${result.isolation_forest.anomaly_score})<br>
          <strong>Random Forest:</strong> ${result.random_forest.verdict} 
          (${result.random_forest.probability})
        `;

        // Update summary section
        document.getElementById("final").innerText = result.final_verdict ?? "N/A";
        document.getElementById("iso").innerText =
            `${result.isolation_forest.verdict} (${result.isolation_forest.anomaly_score})`;
        document.getElementById("rf").innerText =
            `${result.random_forest.verdict} (${result.random_forest.probability})`;

    } catch (err) {
        console.error("Prediction failed:", err);
        document.getElementById("final").innerText = "ERROR";
        document.getElementById("analysis-status").innerText = "Analysis failed!";
        document.getElementById("analysis-output").innerHTML = "";
    }
}