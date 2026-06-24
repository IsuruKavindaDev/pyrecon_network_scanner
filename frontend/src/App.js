import React, { useState, useEffect } from "react";
import axios from "axios";


import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend
} from "recharts";

import ReactFlow from "reactflow";
import "reactflow/dist/style.css";

function App() {

  // =====================================
  // STATES
  // =====================================

  const [ip, setIp] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const [network, setNetwork] = useState("");
  const [devices, setDevices] = useState([]);
  const [discoverLoading, setDiscoverLoading] = useState(false);

  const [publicInfo, setPublicInfo] = useState({});

  // =====================================
  // INTERNET STATUS STATES
  // =====================================

  const [internetStatus, setInternetStatus] = useState({});
  const [internetLoading, setInternetLoading] = useState(false);

  // =====================================
  // DNS RECON STATES
  // =====================================

  const [domain, setDomain] = useState("");
  const [dnsInfo, setDnsInfo] = useState({});
  const [dnsLoading, setDnsLoading] = useState(false);

  // =====================================
  // ANALYTICS COUNTS
  // =====================================

  const criticalCount = results.filter(
    item => item.risk === "CRITICAL"
  ).length;

  const highCount = results.filter(
    item => item.risk === "HIGH"
  ).length;

  const mediumCount = results.filter(
    item => item.risk === "MEDIUM"
  ).length;

  const lowCount = results.filter(
    item => item.risk === "LOW"
  ).length;

  // =====================================
  // RISK CHART DATA
  // =====================================

  const riskData = [

    {
      name: "Critical",
      value: criticalCount
    },

    {
      name: "High",
      value: highCount
    },

    {
      name: "Medium",
      value: mediumCount
    },

    {
      name: "Low",
      value: lowCount
    }

  ];

  // =====================================
  // CHART COLORS
  // =====================================

  const COLORS = [

    "#ef4444",
    "#f97316",
    "#eab308",
    "#22c55e"

  ];

  // =====================================
  // TOPOLOGY NODES
  // =====================================

  const topologyNodes = [

    {
      id: "router",

      position: {
        x: 300,
        y: 50
      },

      data: {
        label: "Main Router"
      },

      style: {
        background: "#0f172a",
        color: "white",
        border: "2px solid cyan",
        padding: 10,
        borderRadius: 10
      }
    },

    ...devices.map((device, index) => ({

      id: device.ip,

      position: {
        x: 100 + (index * 180),
        y: 250
      },

      data: {
        label:
          device.ip +
          "\n" +
          device.device_type
      },

      style: {
        background: "#1e293b",
        color: "white",
        border: "2px solid #22c55e",
        padding: 10,
        width: 170,
        borderRadius: 10,
        textAlign: "center",
        whiteSpace: "pre-line"
      }

    }))

  ];

  // =====================================
  // TOPOLOGY EDGES
  // =====================================

  const topologyEdges = devices.map((device) => ({

    id: "edge-" + device.ip,

    source: "router",

    target: device.ip,

    animated: true,

    style: {
      stroke: "#06b6d4"
    }

  }));

  // =====================================
  // PORT SCAN FUNCTION
  // =====================================

  const startScan = async () => {

    if (!ip) {

      alert("Enter Target IP");
      return;

    }

    setLoading(true);

    try {

      const response = await axios.get(
        "http://localhost:8000/scan?ip=" +
        ip +
        "&start_port=1&end_port=1000"
      );

      setResults(response.data.results);

    } catch (error) {

      console.error(error);

      alert("Scan Failed");

    }

    setLoading(false);

  };

  // =====================================
  // NETWORK DISCOVERY FUNCTION
  // =====================================

  const discoverDevices = async () => {

    if (!network) return;

    setDiscoverLoading(true);

    try {

      const response = await axios.get(
        "http://localhost:8000/discover?network=" +
        network
      );

      setDevices(response.data.devices);

    } catch (error) {

      console.error(error);

      alert("Discovery Failed");

    }

    setDiscoverLoading(false);

  };

  // =====================================
  // ISP + GEOLOCATION FUNCTION
  // =====================================

  const getPublicIPInfo = async () => {

    try {

      const response = await axios.get(
        "http://localhost:8000/public-ip-info"
      );

      setPublicInfo(response.data);

    } catch (error) {

      console.error(error);

    }

  };

  // =====================================
  // INTERNET STATUS FUNCTION
  // =====================================

  const getInternetStatus = async () => {

    setInternetLoading(true);

    try {

      const response = await axios.get(
        "http://localhost:8000/internet-status"
      );

      setInternetStatus(response.data);

    } catch (error) {

      console.error(error);

    }

    setInternetLoading(false);

  };

  // =====================================
  // DNS RECON FUNCTION
  // =====================================

  const dnsLookup = async () => {

    if (!domain) {

      alert("Enter Domain Name");
      return;

    }

    setDnsLoading(true);

    try {

      const response = await axios.get(
        `http://localhost:8000/dns-info?domain=${domain}`
      );

      setDnsInfo(response.data);

    } catch (error) {

      console.error(error);

      alert("DNS Lookup Failed");

    }

    setDnsLoading(false);

  };

  // =====================================
  // AUTO REFRESH
  // =====================================

  useEffect(() => {

    // Initial Load
    getPublicIPInfo();
    getInternetStatus();

    // Public IP Refresh
    const publicInterval = setInterval(() => {

      getPublicIPInfo();

    }, 10000);

    // Internet Status Refresh
    const internetInterval = setInterval(() => {

      getInternetStatus();

    }, 5000);

    // Device Discovery Refresh
    let discoverInterval;

    if (network) {

      discoverInterval = setInterval(() => {

        discoverDevices();

      }, 10000);

    }

    return () => {

      clearInterval(publicInterval);

      clearInterval(internetInterval);

      if (discoverInterval) {

        clearInterval(discoverInterval);

      }

    };

  }, [network,]);

  // =====================================
  // UI
  // =====================================

  return (

    <div className="min-h-screen bg-slate-950 text-white p-10">

      {/* ================================= */}
      {/* TITLE */}
      {/* ================================= */}

      <h1 className="text-5xl font-bold text-cyan-400 mb-10 text-center">
        PYRECON
      </h1>

      {/* ================================= */}
      {/* INTERNET STATUS MONITOR */}
      {/* ================================= */}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-3">
            Internet Status
          </h2>

          <p
            className={
              internetStatus.internet_status === "ONLINE"
                ? "text-green-400 text-3xl font-bold"
                : "text-red-500 text-3xl font-bold"
            }
          >
            {internetStatus.internet_status}
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-3">
            Latency
          </h2>

          <p className="text-3xl font-bold text-yellow-400">
            {internetStatus.latency_ms} ms
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-3">
            Route Quality
          </h2>

          <p
            className={
              internetStatus.route_quality === "EXCELLENT"
                ? "text-green-400 text-2xl font-bold"
                : internetStatus.route_quality === "GOOD"
                ? "text-yellow-400 text-2xl font-bold"
                : "text-red-500 text-2xl font-bold"
            }
          >
            {internetStatus.route_quality}
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-3">
            Target
          </h2>

          <p className="text-2xl font-bold text-cyan-300">
            {internetStatus.target}
          </p>

        </div>

      </div>

      {/* ================================= */}
      {/* PUBLIC IP INFORMATION */}
      {/* ================================= */}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-2">
            Public IP
          </h2>

          <p className="text-2xl font-bold">
            {publicInfo.public_ip}
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-2">
            ISP
          </h2>

          <p className="text-2xl font-bold">
            {publicInfo.isp}
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-2">
            Country
          </h2>

          <p className="text-2xl font-bold">
            {publicInfo.country}
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-2">
            City
          </h2>

          <p className="text-2xl font-bold">
            {publicInfo.city}
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-2">
            ASN
          </h2>

          <p className="text-lg font-bold">
            {publicInfo.asn}
          </p>

        </div>

        <div className="bg-slate-900 p-6 rounded-xl shadow-lg">

          <h2 className="text-cyan-400 text-xl mb-2">
            Timezone
          </h2>

          <p className="text-xl font-bold">
            {publicInfo.timezone}
          </p>

        </div>

      </div>

      {/* ================================= */}
      {/* PORT SCANNER */}
      {/* ================================= */}

      <div className="bg-slate-900 p-6 rounded-xl shadow-lg max-w-2xl mx-auto">

        <h2 className="text-2xl font-bold text-cyan-400 mb-4 text-center">
          Port Scanner
        </h2>

        <div className="flex gap-4">

          <input
            type="text"
            placeholder="Enter Target IP"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            className="flex-1 p-3 rounded-lg bg-slate-800 border border-slate-700"
          />

          <button
            onClick={startScan}
            className="bg-cyan-500 hover:bg-cyan-600 px-6 py-3 rounded-lg font-semibold"
          >
            Scan
          </button>

        </div>

      </div>

      {/* ================================= */}
      {/* NETWORK DISCOVERY */}
      {/* ================================= */}

      <div className="bg-slate-900 p-6 rounded-xl shadow-lg max-w-2xl mx-auto mt-10">

        <h2 className="text-2xl font-bold text-green-400 mb-4 text-center">
          Network Discovery
        </h2>

        <div className="flex gap-4">

          <input
            type="text"
            placeholder="Example: 192.168.1"
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
            className="flex-1 p-3 rounded-lg bg-slate-800 border border-slate-700"
          />

          <button
            onClick={discoverDevices}
            className="bg-green-500 hover:bg-green-600 px-6 py-3 rounded-lg font-semibold"
          >
            Discover
          </button>

        </div>

      </div>

      {/* ================================= */}
      {/* DNS RECONNAISSANCE */}
      {/* ================================= */}

      <div className="bg-slate-900 p-6 rounded-xl shadow-lg max-w-5xl mx-auto mt-10">

        <h2 className="text-2xl font-bold text-purple-400 mb-4 text-center">
          DNS Reconnaissance
        </h2>

        <div className="flex gap-4">

          <input
            type="text"
            placeholder="Enter Domain (example: google.com)"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="flex-1 p-3 rounded-lg bg-slate-800 border border-slate-700"
          />

          <button
            onClick={dnsLookup}
            className="bg-purple-500 hover:bg-purple-600 px-6 py-3 rounded-lg font-semibold"
          >
            Lookup
          </button>

        </div>

      </div>

      {/* ================================= */}
      {/* DNS LOADING */}
      {/* ================================= */}

      {dnsLoading && (

        <div className="text-center mt-8 text-purple-400 text-xl">
          Gathering DNS Information...
        </div>

      )}

      {/* ================================= */}
      {/* DNS RESULTS */}
      {/* ================================= */}

      {dnsInfo.domain && (

        <div className="mt-10 max-w-7xl mx-auto">

          <h2 className="text-3xl font-bold text-purple-400 mb-6 text-center">
            DNS Reconnaissance Results
          </h2>

          <div className="overflow-x-auto">

<tbody>

<tr>
  <td className="p-4 border border-slate-700 font-bold">
    Domain
  </td>
  <td className="p-4 border border-slate-700">
    {dnsInfo.domain}
  </td>
</tr>

<tr>
  <td className="p-4 border border-slate-700 font-bold">
    A Records
  </td>
  <td className="p-4 border border-slate-700 text-cyan-400">
    {dnsInfo.dns_records?.A?.join(", ") || "N/A"}
  </td>
</tr>

<tr>
  <td className="p-4 border border-slate-700 font-bold">
    AAAA Records
  </td>
  <td className="p-4 border border-slate-700 text-cyan-400">
    {dnsInfo.dns_records?.AAAA?.join(", ") || "N/A"}
  </td>
</tr>

<tr>
  <td className="p-4 border border-slate-700 font-bold">
    MX Records
  </td>
  <td className="p-4 border border-slate-700">
    {dnsInfo.dns_records?.MX?.join(", ") || "N/A"}
  </td>
</tr>

<tr>
  <td className="p-4 border border-slate-700 font-bold">
    NS Records
  </td>
  <td className="p-4 border border-slate-700">
    {dnsInfo.dns_records?.NS?.join(", ") || "N/A"}
  </td>
</tr>

<tr>
  <td className="p-4 border border-slate-700 font-bold">
    TXT Records
  </td>
  <td className="p-4 border border-slate-700">
    {dnsInfo.dns_records?.TXT?.join(" | ") || "N/A"}
  </td>
</tr>

</tbody>

          </div>

        </div>

      )}

      {/* ================================= */}
      {/* LOADING */}
      {/* ================================= */}

      {loading && (

        <div className="text-center mt-10 text-cyan-400 text-xl">
          Scanning Target...
        </div>

      )}

      {discoverLoading && (

        <div className="text-center mt-10 text-green-400 text-xl">
          Discovering Devices...
        </div>

      )}

      {internetLoading && (

        <div className="text-center mt-10 text-yellow-400 text-xl">
          Monitoring Internet...
        </div>

      )}

      {/* ================================= */}
      {/* NETWORK TOPOLOGY */}
      {/* ================================= */}

      {devices.length > 0 && (

        <div className="mt-10 max-w-7xl mx-auto">

          <div className="bg-slate-900 rounded-xl p-6 shadow-lg">

            <h2 className="text-3xl font-bold text-cyan-400 mb-6 text-center">
              Network Topology
            </h2>

            <div style={{ height: "500px" }}>

              <ReactFlow
                nodes={topologyNodes}
                edges={topologyEdges}
                fitView
              />

            </div>

          </div>

        </div>

      )}

      {/* ================================= */}
      {/* CONNECTED DEVICES */}
      {/* ================================= */}

      {devices.length > 0 && (

        <div className="mt-10 max-w-7xl mx-auto">

          <h2 className="text-3xl font-bold text-green-400 mb-6 text-center">
            Connected Devices
          </h2>

          <table className="w-full border-collapse">

            <thead>

              <tr className="bg-slate-800">

                <th className="p-4 border border-slate-700">
                  IP Address
                </th>

                <th className="p-4 border border-slate-700">
                  Hostname
                </th>

                <th className="p-4 border border-slate-700">
                  Device Type
                </th>

                <th className="p-4 border border-slate-700">
                  MAC Address
                </th>

                <th className="p-4 border border-slate-700">
                  Vendor
                </th>

                <th className="p-4 border border-slate-700">
                  Status
                </th>

              </tr>

            </thead>

            <tbody>

              {devices.map((device, index) => (

                <tr
                  key={index}
                  className="text-center hover:bg-slate-800"
                >

                  <td className="p-4 border border-slate-700">
                    {device.ip}
                  </td>

                  <td className="p-4 border border-slate-700 text-cyan-400">
                    {device.hostname}
                  </td>

                  <td className="p-4 border border-slate-700">
                    {device.device_type}
                  </td>

                  <td className="p-4 border border-slate-700 text-orange-400 font-semibold">
                    {device.mac_address}
                  </td>

                  <td className="p-4 border border-slate-700 text-pink-400 font-semibold">
                    {device.vendor}
                  </td>

                  <td className="p-4 border border-slate-700 text-green-400 font-bold">
                    {device.status}
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>

      )}

      {/* ================================= */}
      {/* ANALYTICS */}
      {/* ================================= */}

      {results.length > 0 && (

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-10 max-w-6xl mx-auto">

          <div className="bg-slate-900 p-6 rounded-xl shadow-lg text-center">

            <h2 className="text-xl text-cyan-400">
              Open Ports
            </h2>

            <p className="text-4xl font-bold mt-3">
              {results.length}
            </p>

          </div>

          <div className="bg-slate-900 p-6 rounded-xl shadow-lg text-center">

            <h2 className="text-xl text-red-500">
              Critical
            </h2>

            <p className="text-4xl font-bold mt-3">
              {criticalCount}
            </p>

          </div>

          <div className="bg-slate-900 p-6 rounded-xl shadow-lg text-center">

            <h2 className="text-xl text-orange-400">
              High
            </h2>

            <p className="text-4xl font-bold mt-3">
              {highCount}
            </p>

          </div>

          <div className="bg-slate-900 p-6 rounded-xl shadow-lg text-center">

            <h2 className="text-xl text-green-400">
              Low
            </h2>

            <p className="text-4xl font-bold mt-3">
              {lowCount}
            </p>

          </div>

        </div>

      )}

      {/* ================================= */}
      {/* RISK ANALYTICS */}
      {/* ================================= */}

      {results.length > 0 && (

        <div className="mt-10 flex justify-center">

          <div className="bg-slate-900 p-8 rounded-xl shadow-lg">

            <h2 className="text-2xl text-cyan-400 font-bold mb-6 text-center">
              Risk Analytics
            </h2>

            <PieChart width={400} height={300}>

              <Pie
                data={riskData}
                cx="50%"
                cy="50%"
                outerRadius={100}
                dataKey="value"
                label
              >

                {riskData.map((entry, index) => (

                  <Cell
                    key={`cell-${index}`}
                    fill={COLORS[index % COLORS.length]}
                  />

                ))}

              </Pie>

              <Tooltip />

              <Legend />

            </PieChart>

          </div>

        </div>

      )}

      {/* ================================= */}
      {/* PORT RESULTS */}
      {/* ================================= */}

      {results.length > 0 && (

        <div className="mt-10 max-w-7xl mx-auto">

          <h2 className="text-3xl font-bold text-cyan-400 mb-6 text-center">
            CVE Vulnerability Scan Results
          </h2>

          <div className="overflow-x-auto">

            <table className="w-full border-collapse">

              <thead>

                <tr className="bg-slate-800">

                  <th className="p-4 border border-slate-700">
                    Port
                  </th>

                  <th className="p-4 border border-slate-700">
                    Service
                  </th>

                  <th className="p-4 border border-slate-700">
                    Status
                  </th>

                  <th className="p-4 border border-slate-700">
                    Risk
                  </th>

                  <th className="p-4 border border-slate-700">
                    Banner
                  </th>

                  <th className="p-4 border border-slate-700">
                    CVE
                  </th>

                  <th className="p-4 border border-slate-700">
                    Vulnerability
                  </th>

                  <th className="p-4 border border-slate-700">
                    Severity
                  </th>

                </tr>

              </thead>

              <tbody>

                {results.map((item, index) => (

                  <tr
                    key={index}
                    className="text-center hover:bg-slate-800"
                  >

                    <td className="p-4 border border-slate-700 font-bold">
                      {item.port}
                    </td>

                    <td className="p-4 border border-slate-700">
                      {item.service}
                    </td>

                    <td className="p-4 border border-slate-700 text-green-400 font-bold">
                      {item.status}
                    </td>

                    <td className="p-4 border border-slate-700">

                      <span
                        className={
                          item.risk === "CRITICAL"
                            ? "text-red-500 font-bold"
                            : item.risk === "HIGH"
                            ? "text-orange-400 font-bold"
                            : item.risk === "MEDIUM"
                            ? "text-yellow-400 font-bold"
                            : "text-green-400 font-bold"
                        }
                      >
                        {item.risk}
                      </span>

                    </td>

                    <td className="p-4 border border-slate-700 text-cyan-300">
                      {item.banner}
                    </td>

                    <td className="p-4 border border-slate-700 text-pink-400 font-bold">
                      {item.cve}
                    </td>

                    <td className="p-4 border border-slate-700 text-yellow-300">
                      {item.vulnerability}
                    </td>

                    <td className="p-4 border border-slate-700">

                      <span
                        className={
                          item.severity === "CRITICAL"
                            ? "text-red-500 font-bold"
                            : item.severity === "HIGH"
                            ? "text-orange-400 font-bold"
                            : item.severity === "MEDIUM"
                            ? "text-yellow-400 font-bold"
                            : "text-green-400 font-bold"
                        }
                      >
                        {item.severity}
                      </span>

                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        </div>

      )}

      {/* ================================= */}
      {/* DOWNLOAD PDF REPORT BUTTON */}
      {/* ================================= */}

      {results.length > 0 && (

        <div className="mt-10 flex justify-center">

          <button

            onClick={() => {

              window.open(
                "http://localhost:8000/generate-report",
                "_blank"
              );

            }}

            className="
              bg-red-600
              hover:bg-red-700
              px-8
              py-4
              rounded-xl
              text-white
              font-bold
              text-lg
              shadow-lg
            "
          >

            Download Security PDF Report

          </button>

        </div>

      )}

    </div>

  );

}

export default App;