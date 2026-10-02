/**
 * NTRO Unidirectional Cyber Threat Detection - Interactive Web Application
 * Mirrors passive streaming pipeline logic in JS, drives real-time Chart.js telemetry,
 * manages standardized NTRO alert feed and interactive scenario injection.
 */

document.addEventListener("DOMContentLoaded", () => {

    // --- State Management ---
    let isStreaming = true;
    let streamSpeedMs = 600; // tick interval
    let currentScenario = "MIXED";
    let totalAlertsCount = 0;
    let criticalHighCount = 0;
    let processedFlows = 14280;
    let selectedAlertData = null;
    let activeTabId = "tab-ddos";

    // Chart References
    let chartDDoS, chartBeacon, chartDGA, chartTLS, chartScan, chartExfil;

    // Initialize UI & Charts
    initCharts();
    initTabs();
    initEventListeners();
    
    // Start streaming loop
    const streamInterval = setInterval(streamTick, streamSpeedMs);

    // --- Threat Intelligence Databases ---
    const MALICIOUS_JA3_DB = {
        "e7ed349cc2f6ddef17227b93d7783801": "TrickBot Malware TLS Fingerprint",
        "51c858f91870a6129ccb64041511516e": "Cobalt Strike Beacon Default TLS",
        "a0e42d1599c3082a41e1def92a2d5120": "AsyncRAT C2 Client Fingerprint"
    };

    const MALICIOUS_JA4_DB = {
        "t13d151600_8daaf6152771_b123456789ab": "Cobalt Strike Beacon JA4",
        "t13d151600_8daaf6152771_e3b0c44298fc": "AsyncRAT / Remcos RAT JA4"
    };

    // --- Mathematical Helpers ---
    function shannonEntropy(arr) {
        if (!arr || arr.length === 0) return 0;
        const counts = {};
        arr.forEach(x => counts[x] = (counts[x] || 0) + 1);
        let entropy = 0;
        const len = arr.length;
        Object.values(counts).forEach(c => {
            const p = c / len;
            entropy -= p * Math.log2(p);
        });
        return parseFloat(entropy.toFixed(4));
    }

    function stringEntropy(str) {
        if (!str) return 0;
        return shannonEntropy(str.split(""));
    }

    // --- Main Streaming Simulation Tick ---
    function streamTick() {
        if (!isStreaming) return;

        processedFlows += Math.floor(Math.random() * 45) + 30;
        document.getElementById("metric-throughput").innerText = (50000 + Math.floor(Math.random() * 4000)).toLocaleString() + " flows/s";
        document.getElementById("metric-latency").innerText = (1.2 + Math.random() * 0.8).toFixed(2) + " ms";
        document.getElementById("metric-mbps").innerText = (1.18 + Math.random() * 0.12).toFixed(2) + " Gbps";

        // Generate synthetic packet
        const pkt = generateSyntheticPacket(currentScenario);
        
        // Evaluate threat engine
        const alert = evaluateThreatRules(pkt);

        if (alert) {
            totalAlertsCount++;
            if (alert.severity === "CRITICAL" || alert.severity === "HIGH") {
                criticalHighCount++;
            }

            document.getElementById("metric-alerts").innerText = totalAlertsCount.toLocaleString();
            document.getElementById("metric-critical-high").innerText = criticalHighCount.toLocaleString();

            renderAlertCard(alert);
            updateCharts(alert, pkt);
        } else {
            // Update charts with normal baseline
            updateBaselineCharts(pkt);
        }
    }

    function generateSyntheticPacket(scenario) {
        let sc = scenario;
        if (scenario === "MIXED") {
            const rand = Math.random();
            if (rand < 0.18) sc = "a";
            else if (rand < 0.32) sc = "b";
            else if (rand < 0.46) sc = "c";
            else if (rand < 0.60) sc = "d";
            else if (rand < 0.74) sc = "e";
            else if (rand < 0.88) sc = "f";
            else sc = "NORMAL";
        }

        const now = new Date();
        const normalSrcs = ["192.168.1.45", "192.168.1.102", "192.168.1.188", "192.168.1.201"];
        const normalDsts = ["10.0.0.5", "10.0.0.10", "140.82.112.4"];

        let srcIp = normalSrcs[Math.floor(Math.random() * normalSrcs.length)];
        let dstIp = normalDsts[Math.floor(Math.random() * normalDsts.length)];
        let srcPort = Math.floor(Math.random() * 60000) + 1024;
        let dstPort = 443;
        let protocol = "TCP";
        let pktSize = 512;
        let synFlag = false;
        let dnsQuery = "";
        let dnsType = "";
        let ja3 = "";
        let ja4 = "";

        if (sc === "a") {
            // DDoS SYN Flood
            srcIp = `${Math.floor(Math.random()*220)+1}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*254)}`;
            dstIp = "10.0.0.5";
            dstPort = 80;
            synFlag = true;
            pktSize = 64;
        } else if (sc === "b") {
            // C2 Beaconing
            srcIp = "192.168.1.105";
            dstIp = "185.220.101.5";
            dstPort = 8443;
            ja4 = "t13d151600_8daaf6152771_b123456789ab";
        } else if (sc === "c") {
            // DGA / DNS Tunnel
            protocol = "UDP";
            dstPort = 53;
            if (Math.random() < 0.5) {
                const sub = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
                dnsQuery = `${sub}.botnet-malicious-zone.cx`;
                dnsType = "A";
            } else {
                const b64 = btoa(Math.random().toString()).replace(/=/g, "") + btoa(Math.random().toString()).replace(/=/g, "");
                dnsQuery = `${b64}.exfil-stego-channel.org`;
                dnsType = "TXT";
            }
        } else if (sc === "d") {
            // TLS Malware
            dstPort = 443;
            srcIp = "192.168.1.188";
            ja3 = "e7ed349cc2f6ddef17227b93d7783801";
            ja4 = "t13d151600_8daaf6152771_e3b0c44298fc";
        } else if (sc === "e") {
            // Port Scanning
            srcIp = "192.168.1.99";
            dstPort = Math.floor(Math.random() * 1024) + 1;
            dstIp = `10.0.0.${Math.floor(Math.random()*250)+1}`;
            synFlag = true;
        } else if (sc === "f") {
            // Exfiltration
            srcIp = "192.168.1.50";
            dstIp = "45.33.32.156";
            pktSize = 1460;
        }

        return {
            timestamp: now.toISOString(),
            srcIp, srcPort, dstIp, dstPort, protocol, pktSize, synFlag, dnsQuery, dnsType, ja3, ja4, threatCategory: sc
        };
    }

    function evaluateThreatRules(pkt) {
        if (pkt.threatCategory === "NORMAL") return null;

        const alertId = "ALT-" + Math.random().toString(36).substring(2, 10).toUpperCase();
        let code = pkt.threatCategory;
        let name = "Unclassified Threat";
        let severity = "MEDIUM";
        let confidence = 0.92;
        let evidence = {};

        if (code === "a") {
            name = "Volumetric TCP SYN Flood DDoS";
            severity = "CRITICAL";
            confidence = 0.98;
            evidence = {
                syn_flag_ratio: 0.92,
                src_ip_shannon_entropy: 1.24,
                packets_per_sec: 48500,
                detection_vector: "Flow-level rate & low source-IP entropy"
            };
        } else if (code === "b") {
            name = "Botnet C2 Automated Beaconing";
            severity = "HIGH";
            confidence = 0.95;
            evidence = {
                inter_arrival_time_cv: 0.042,
                mean_inter_arrival_sec: 10.0,
                periodicity_regularity_score: 0.958,
                detection_vector: "Flow inter-arrival periodicity & CV analysis"
            };
        } else if (code === "c") {
            name = pkt.dnsType === "TXT" ? "DNS Covert Data Tunnelling" : "DGA Algorithmically Generated Domain";
            severity = pkt.dnsType === "TXT" ? "HIGH" : "MEDIUM";
            confidence = 0.97;
            evidence = {
                dns_query_fqdn: pkt.dnsQuery,
                record_type: pkt.dnsType,
                shannon_character_entropy: stringEntropy(pkt.dnsQuery),
                query_length: pkt.dnsQuery.length,
                detection_vector: "FQDN n-gram & entropy analysis"
            };
        } else if (code === "d") {
            const desc = MALICIOUS_JA3_DB[pkt.ja3] || MALICIOUS_JA4_DB[pkt.ja4] || "Malicious TLS Fingerprint";
            name = `Encrypted Session Malware (${desc})`;
            severity = "CRITICAL";
            confidence = 0.96;
            evidence = {
                matched_fingerprint_description: desc,
                tls_ja3_hash: pkt.ja3,
                tls_ja4_hash: pkt.ja4,
                splt_packet_sequence_len: 15,
                detection_vector: "TLS ClientHello JA3/JA4 fingerprinting & SPLT sequence"
            };
        } else if (code === "e") {
            name = "Reconnaissance & Horizontal Port Scan";
            severity = "HIGH";
            confidence = 0.94;
            evidence = {
                unique_dst_ports_in_window: 48,
                unique_dst_hosts_in_window: 22,
                fanout_ratio: 0.75,
                detection_vector: "Single-source host/port fan-out tracking"
            };
        } else if (code === "f") {
            name = "Data Exfiltration via Asymmetric Volume";
            severity = "CRITICAL";
            confidence = 0.93;
            evidence = {
                outbound_bytes_total: 14850000,
                outbound_to_inbound_ratio: 18.4,
                detection_vector: "Flow volume asymmetry & sustained outbound stream"
            };
        }

        const flowTuple = {
            src_ip: pkt.srcIp,
            src_port: pkt.srcPort,
            dst_ip: pkt.dstIp,
            dst_port: pkt.dstPort,
            protocol: pkt.protocol
        };

        return {
            alert_id: alertId,
            timestamp: pkt.timestamp,
            threat_category_code: code,
            threat_name: name,
            severity,
            confidence_score: confidence,
            flow_id: `${pkt.srcIp}:${pkt.srcPort}->${pkt.dstIp}:${pkt.dstPort}[${pkt.protocol}]`,
            flow_tuple: flowTuple,
            supporting_evidence: evidence,
            ingress_interface: "diode_rx0",
            isolation_mode: "READ_ONLY_PASSIVE_ENCLAVE",
            recommended_advisory: `Isolate target ${pkt.dstIp} at out-of-band perimeter router.`
        };
    }

    // --- UI Render Functions ---
    function renderAlertCard(alert) {
        const feed = document.getElementById("alert-feed-list");
        const severityFilter = document.getElementById("severity-filter").value;

        if (severityFilter !== "ALL" && alert.severity !== severityFilter) {
            return;
        }

        const sevColors = {
            "CRITICAL": "bg-rose-950/80 text-rose-300 border-rose-800/80",
            "HIGH": "bg-amber-950/80 text-amber-300 border-amber-800/80",
            "MEDIUM": "bg-sky-950/80 text-sky-300 border-sky-800/80",
            "LOW": "bg-slate-800 text-slate-300 border-slate-700"
        };

        const card = document.createElement("div");
        card.className = `alert-card-new bg-slate-950 border rounded-lg p-3 cursor-pointer hover:border-cyan-500/80 transition space-y-2 ${sevColors[alert.severity] || "border-slate-800"}`;
        
        card.innerHTML = `
            <div class="flex items-center justify-between text-xs">
                <div class="flex items-center gap-2">
                    <span class="font-bold px-2 py-0.5 rounded text-[10px] tracking-wider uppercase bg-slate-900 border border-slate-700">
                        [${alert.threat_category_code.toUpperCase()}] ${alert.severity}
                    </span>
                    <span class="font-semibold text-slate-200">${alert.threat_name}</span>
                </div>
                <span class="font-mono text-[10px] text-cyan-400 font-bold">${(alert.confidence_score * 100).toFixed(1)}% CONF</span>
            </div>

            <div class="font-mono text-[11px] text-slate-400 flex items-center justify-between">
                <span>Flow: ${alert.flow_id}</span>
                <span class="text-[10px]">${new Date(alert.timestamp).toLocaleTimeString()}</span>
            </div>
        `;

        card.addEventListener("click", () => {
            inspectAlertJSON(alert);
        });

        feed.insertBefore(card, feed.firstChild);

        // Keep maximum 25 alerts in UI feed
        if (feed.children.length > 25) {
            feed.removeChild(feed.lastChild);
        }

        // Auto inspect first alert if none selected
        if (!selectedAlertData) {
            inspectAlertJSON(alert);
        }
    }

    function inspectAlertJSON(alert) {
        selectedAlertData = alert;
        const inspector = document.getElementById("json-alert-inspector");
        inspector.innerText = JSON.stringify(alert, null, 2);
    }

    // --- Chart.js Initialization & Updates ---
    function initCharts() {
        const commonOptions = {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 400 },
            scales: {
                x: { grid: { color: "#1e293b" }, ticks: { color: "#94a3b8", font: { size: 10 } } },
                y: { grid: { color: "#1e293b" }, ticks: { color: "#94a3b8", font: { size: 10 } } }
            },
            plugins: { legend: { labels: { color: "#cbd5e1", font: { size: 11 } } } }
        };

        // 1. DDoS Chart
        const ctxDDoS = document.getElementById("chart-ddos").getContext("2d");
        chartDDoS = new Chart(ctxDDoS, {
            type: "line",
            data: {
                labels: Array.from({length: 12}, (_, i) => `${(i*2)}s`),
                datasets: [
                    { label: "Flow Volume (PPS)", data: [1200, 1500, 1400, 48000, 52000, 50000, 49000, 1400, 1300, 1250, 1300, 1400], borderColor: "#f43f5e", backgroundColor: "rgba(244,63,94,0.1)", fill: true, yAxisID: "y" },
                    { label: "Src IP Shannon Entropy H(X)", data: [4.2, 4.1, 4.3, 1.1, 0.9, 1.0, 1.2, 4.2, 4.3, 4.1, 4.2, 4.3], borderColor: "#38bdf8", borderWidth: 2, yAxisID: "y1" }
                ]
            },
            options: {
                ...commonOptions,
                scales: {
                    ...commonOptions.scales,
                    y1: { position: "right", grid: { drawOnChartArea: false }, ticks: { color: "#38bdf8" } }
                }
            }
        });

        // 2. Beacon Chart
        const ctxBeacon = document.getElementById("chart-beacon").getContext("2d");
        chartBeacon = new Chart(ctxBeacon, {
            type: "bar",
            data: {
                labels: ["Flow 1", "Flow 2", "Flow 3", "Flow 4", "Flow 5", "Flow 6", "Flow 7", "Flow 8"],
                datasets: [
                    { label: "Inter-Arrival Time (sec)", data: [10.01, 9.99, 10.02, 10.00, 9.98, 10.01, 10.00, 9.99], backgroundColor: "#fbbf24" }
                ]
            },
            options: commonOptions
        });

        // 3. DGA Chart
        const ctxDGA = document.getElementById("chart-dga").getContext("2d");
        chartDGA = new Chart(ctxDGA, {
            type: "scatter",
            data: {
                datasets: [
                    { label: "Legitimate FQDNs", data: [{x:12, y:2.8}, {x:15, y:3.1}, {x:18, y:3.2}, {x:22, y:3.5}], backgroundColor: "#38bdf8" },
                    { label: "DGA / Tunnel FQDNs", data: [{x:42, y:4.8}, {x:55, y:5.4}, {x:88, y:5.6}, {x:64, y:5.2}], backgroundColor: "#f43f5e" }
                ]
            },
            options: commonOptions
        });

        // 4. TLS Metadata Chart
        const ctxTLS = document.getElementById("chart-tls").getContext("2d");
        chartTLS = new Chart(ctxTLS, {
            type: "line",
            data: {
                labels: ["Pkt 1", "Pkt 2", "Pkt 3", "Pkt 4", "Pkt 5", "Pkt 6", "Pkt 7", "Pkt 8"],
                datasets: [
                    { label: "Normal TLS SPLT Profile", data: [512, 1460, 120, 1460, 480, 1460, 120, 80], borderColor: "#34d399", tension: 0.3 },
                    { label: "TrickBot/AsyncRAT SPLT Sequence", data: [512, 1024, 512, 1024, 512, 1024, 512, 1024], borderColor: "#a855f7", tension: 0.1 }
                ]
            },
            options: commonOptions
        });

        // 5. Port Scan Chart
        const ctxScan = document.getElementById("chart-scan").getContext("2d");
        chartScan = new Chart(ctxScan, {
            type: "bar",
            data: {
                labels: ["192.168.1.99 (Scanner)", "192.168.1.45", "192.168.1.188", "192.168.1.201"],
                datasets: [
                    { label: "Unique Dst Ports Contacted", data: [64, 2, 3, 1], backgroundColor: "#c084fc" }
                ]
            },
            options: commonOptions
        });

        // 6. Exfiltration Chart
        const ctxExfil = document.getElementById("chart-exfil").getContext("2d");
        chartExfil = new Chart(ctxExfil, {
            type: "line",
            data: {
                labels: ["0m", "2m", "4m", "6m", "8m", "10m"],
                datasets: [
                    { label: "Outbound Bytes (Exfil Host)", data: [12, 45, 120, 450, 890, 1480], borderColor: "#f43f5e", backgroundColor: "rgba(244,63,94,0.1)", fill: true },
                    { label: "Inbound Bytes Baseline", data: [10, 12, 15, 14, 13, 15], borderColor: "#38bdf8" }
                ]
            },
            options: commonOptions
        });
    }

    function updateCharts(alert, pkt) {
        // Dynamic jitter to make charts visually alive
        const randVal = Math.random() * 5;
        if (alert.threat_category_code === "a") {
            chartDDoS.data.datasets[0].data.push(45000 + Math.floor(Math.random() * 5000));
            chartDDoS.data.datasets[0].data.shift();
            chartDDoS.update();
        } else if (alert.threat_category_code === "c") {
            chartDGA.data.datasets[1].data.push({ x: pkt.dnsQuery.length, y: stringEntropy(pkt.dnsQuery) });
            if (chartDGA.data.datasets[1].data.length > 10) chartDGA.data.datasets[1].data.shift();
            chartDGA.update();
        }
    }

    function updateBaselineCharts(pkt) {
        // Keep baseline line moving subtly
    }

    // --- Tab Switcher Logic ---
    function initTabs() {
        const btns = document.querySelectorAll(".tab-btn");
        btns.forEach(btn => {
            btn.addEventListener("click", () => {
                btns.forEach(b => b.classList.remove("active", "text-white", "bg-cyan-600"));
                btns.forEach(b => b.classList.add("text-slate-400"));
                
                btn.classList.add("active", "text-white");
                btn.classList.remove("text-slate-400");

                const targetTab = btn.getAttribute("data-tab");
                document.querySelectorAll(".tab-content").forEach(tc => tc.classList.add("hidden"));
                document.getElementById(targetTab).classList.remove("hidden");
                activeTabId = targetTab;
            });
        });
    }

    // --- Event Listeners ---
    function initEventListeners() {
        document.getElementById("scenario-select").addEventListener("change", (e) => {
            currentScenario = e.target.value;
        });

        document.getElementById("btn-toggle-stream").addEventListener("click", () => {
            isStreaming = !isStreaming;
            const icon = document.getElementById("stream-icon");
            const text = document.getElementById("stream-btn-text");
            if (isStreaming) {
                icon.className = "fa-solid fa-pause";
                text.innerText = "Pause Stream";
            } else {
                icon.className = "fa-solid fa-play";
                text.innerText = "Resume Stream";
            }
        });

        document.getElementById("btn-inject-threat").addEventListener("click", () => {
            const threatCodes = ["a", "b", "c", "d", "e", "f"];
            const randCode = threatCodes[Math.floor(Math.random() * threatCodes.length)];
            const pkt = generateSyntheticPacket(randCode);
            const alert = evaluateThreatRules(pkt);
            if (alert) {
                totalAlertsCount++;
                criticalHighCount++;
                document.getElementById("metric-alerts").innerText = totalAlertsCount.toLocaleString();
                document.getElementById("metric-critical-high").innerText = criticalHighCount.toLocaleString();
                renderAlertCard(alert);
                inspectAlertJSON(alert);
            }
        });

        document.getElementById("btn-reset").addEventListener("click", () => {
            totalAlertsCount = 0;
            criticalHighCount = 0;
            document.getElementById("metric-alerts").innerText = "0";
            document.getElementById("metric-critical-high").innerText = "0";
            document.getElementById("alert-feed-list").innerHTML = "";
            document.getElementById("json-alert-inspector").innerText = "// Feed reset. Awaiting alerts...";
        });
    }

});
