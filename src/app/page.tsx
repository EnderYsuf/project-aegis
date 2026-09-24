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

export default function Home() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [aiLogs, setAiLogs] = useState<string[]>([]);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [currentSlogan, setCurrentSlogan] = useState<string>("");

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
    console.log(`File added: ${file.name}`);
    startAiProcess();
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
    }, 2000);
  };

  // timer
  useEffect(() => {
    if (!isThinking) return;

    const timerInterval = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);

    // some quotes
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
        <div className="slogan-badge">AI Diagnostic Engine</div>
        <div className="slogan">
          <p>{currentSlogan}</p>
        </div>
      </div>

      <div className={`upload-wrapper ${isThinking ? "hidden" : ""}`}>
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
