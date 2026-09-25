"use client";

import { useState, useEffect, useRef, ChangeEvent, DragEvent } from "react";
import Image from "next/image";

const AI_THINKING_QUOTES = [
  "thinking...",
  "Thinking more...",
  "Thinking even more...",
  "Should I tell you I'm thinking?",
  "Ooh, I'm soo thinking",
  "I'm AI and I think",
  "Uuu, what is this? Is that thinking?",
];

const SLOGANS = [
  "See what diseases your network is affected by",
  "Diagnose your packet captures before they flatline",
  "Exposing silent network anomalies in real-time",
  "Deep packet analysis with surgical precision",
  "Uncover hidden infections in your digital arteries",
  "Isolate rogue traffic before it spreads",
];

interface FaqItem {
  question: string;
  answer: string;
}

interface AnalysisResult {
  fileName: string;
  totalPackets: number;
  duration: string;
  threatLevel: "Clean" | "Warning" | "Critical";
  detectedAnomalies: { id: string; type: string; severity: "Low" | "Medium" | "High"; detail: string }[];
}

const FAQ_DATA: FaqItem[] = [
  {
    question: "What is a PCAP file and how is it analyzed?",
    answer:
      "A PCAP (Packet Capture) file contains network data logs recorded over time. Our AI engine parses the raw packet payloads, protocols, and metadata to identify anomalies, latency spikes, and malicious security threats.",
  },
  {
    question: "Are my uploaded packet captures stored permanently?",
    answer:
      "No. Uploaded PCAP files are processed in an isolated, secure memory buffer and automatically deleted once your diagnostic session ends. We do not store or train public models on your proprietary traffic data.",
  },
  {
    question: "What is the maximum file size supported?",
    answer:
      "Currently, the web interface supports direct uploads of up to 100 MB per PCAP file. For larger capture files, consider slicing the capture with tshark or Wireshark prior to uploading.",
  },
  {
    question: "What types of network issues can the AI detect?",
    answer:
      "The diagnostic engine scans for suspicious TCP handshakes, port scanning activities, cleartext password leaks, DNS tunneling, unusual bandwidth hogs, and fragmented packet patterns.",
  },
];

export default function Home() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [isFinished, setIsFinished] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [aiLogs, setAiLogs] = useState<string[]>([]);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [currentSlogan, setCurrentSlogan] = useState<string>("");
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(null);

  const logsEndRef = useRef<HTMLDivElement | null>(null);

  // pick a random slogan on page load
  useEffect(() => {
    const randomSlogan = SLOGANS[Math.floor(Math.random() * SLOGANS.length)];
    setCurrentSlogan(randomSlogan);
  }, []);

  // auto scroll
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [aiLogs]);

  // file input
  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setIsFinished(false);
    setAnalysisResult(null);
    setAiLogs([]);
    setElapsedSeconds(0);
    console.log(`File added: ${file.name}`);
    startAiProcess();
  };

  // result display
  const resultShow = () => {
    setIsThinking(false);
    setIsFinished(true);
    setAnalysisResult({
      fileName: selectedFile?.name || "network_capture.pcap",
      totalPackets: 142850,
      duration: "00:14:32",
      threatLevel: "Critical",
      detectedAnomalies: [
        {
          id: "ANOM-01",
          type: "DNS Tunneling",
          severity: "High",
          detail: "High-frequency TXT requests detected targeting external host (185.220.101.4).",
        },
        {
          id: "ANOM-02",
          type: "TCP SYN Flood",
          severity: "High",
          detail: "4,200 incomplete TCP handshakes targeted at internal server 10.0.4.12:80.",
        },
        {
          id: "ANOM-03",
          type: "Cleartext Transmission",
          severity: "Medium",
          detail: "HTTP POST payload contains unencrypted credentials on port 8080.",
        },
      ],
    });
  };

  const handleInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
    }
  };

  const handleDragOver = (e: DragEvent<HTMLLabelElement>) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLLabelElement>) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: DragEvent<HTMLLabelElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const startAiProcess = () => {
    setTimeout(() => {
      setIsThinking(true);
      endAiProcess();
    }, 2000);
  };

  const endAiProcess = () => {
    const randomTime = Math.random() * 4000 + 3000;
    setTimeout(() => {
      resultShow();
    }, randomTime);
  };

  const toggleFaq = (index: number) => {
    setOpenFaqIndex(openFaqIndex === index ? null : index);
  };

  const handleReset = () => {
    setSelectedFile(null);
    setIsThinking(false);
    setIsFinished(false);
    setAnalysisResult(null);
  };

  // timer
  useEffect(() => {
    if (!isThinking) return;

    const timerInterval = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);

    const quoteInterval = setInterval(() => {
      const randomQuote =
        AI_THINKING_QUOTES[
          Math.floor(Math.random() * AI_THINKING_QUOTES.length)
        ];
      setAiLogs((prev) => [...prev, randomQuote]);
    }, 1000);

    return () => {
      clearInterval(timerInterval);
      clearInterval(quoteInterval);
    };
  }, [isThinking]);

  return (
    <>
      <div className="top-bar">
        <div className="brand-wrapper">
          <div className="logo-container">
            <Image
              src="/logo.png"
              alt="logo"
              width={36}
              height={36}
              className="logo-image"
            />
          </div>
        </div>
      </div>

      <div className="hero-section">
        <div className="slogan-badge">AI PCAP Diagnostic Engine</div>
        <div className="slogan">
          <p>{currentSlogan}</p>
        </div>
      </div>

      {/* 1. Results Display Area placed BEFORE Upload Wrapper */}
      {isFinished && analysisResult && (
        <div className="result-wrapper">
          <div className="result-card">
            <div className="result-header">
              <div>
                <h3 className="result-title">Diagnostic Report</h3>
                <p className="result-filename">{analysisResult.fileName}</p>
              </div>
              <span className={`badge-alert ${analysisResult.threatLevel.toLowerCase()}`}>
                {analysisResult.threatLevel} Threat Level
              </span>
            </div>

            <div className="result-metrics">
              <div className="metric-box">
                <span className="metric-label">Total Packets</span>
                <span className="metric-value">{analysisResult.totalPackets.toLocaleString()}</span>
              </div>
              <div className="metric-box">
                <span className="metric-label">Capture Duration</span>
                <span className="metric-value">{analysisResult.duration}</span>
              </div>
              <div className="metric-box">
                <span className="metric-label">Anomalies Detected</span>
                <span className="metric-value text-neon">{analysisResult.detectedAnomalies.length}</span>
              </div>
            </div>

            <div className="anomalies-section">
              <h4>Detected Security Anomalies</h4>
              <div className="anomalies-list">
                {analysisResult.detectedAnomalies.map((item) => (
                  <div key={item.id} className="anomaly-item">
                    <div className="anomaly-header">
                      <span className="anomaly-type">{item.type}</span>
                      <span className={`severity-badge ${item.severity.toLowerCase()}`}>
                        {item.severity}
                      </span>
                    </div>
                    <p className="anomaly-detail">{item.detail}</p>
                  </div>
                ))}
              </div>
            </div>

            <button className="btn-primary reset-btn" onClick={handleReset}>
              Analyze Another PCAP File
            </button>
          </div>
        </div>
      )}

      {/* 2. File Upload Wrapper */}
      <div className={`upload-wrapper ${isThinking || isFinished ? "hidden" : ""}`}>
        <label
          className={`file-upload ${isDragOver ? "dragover" : ""}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <input
            type="file"
            accept=".pcap"
            id="fileInput"
            onChange={handleInputChange}
          />
          <svg
            className="upload-icon"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
            />
          </svg>
          <div className="upload-title">
            Drag & drop files or <span>Browse</span>
          </div>
          <div className="upload-hint">
            Supports packet capture files (.pcap)
          </div>
        </label>
      </div>

      {/* 3. FAQ Section */}
      <div className={`faq-wrapper ${isThinking || isFinished ? "hidden" : ""}`}>
        <h2 className="faq-title">Frequently Asked Questions</h2>
        <div className="faq-list">
          {FAQ_DATA.map((item, index) => {
            const isOpen = openFaqIndex === index;
            return (
              <div
                key={index}
                className={`faq-item ${isOpen ? "open" : ""}`}
                onClick={() => toggleFaq(index)}
              >
                <div className="faq-question">
                  <span>{item.question}</span>
                  <svg
                    className="faq-icon"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </div>
                {isOpen && <div className="faq-answer">{item.answer}</div>}
              </div>
            );
          })}
        </div>
      </div>

      {/* 4. AI Thinking Terminal */}
      <div className={`ai-actions-window ${isThinking ? "show" : ""}`}>
        <div className="ai-actions-header">
          Thinking... ({elapsedSeconds} seconds)
        </div>
        <div className="ai-logs-container">
          {aiLogs.map((quote, index) => (
            <div key={index} className="ai-log-entry">
              {quote}
            </div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>
    </>
  );
}
