import React, {
  useEffect,
  useState,
  useRef,
  useCallback,
  useContext,
} from "react";
import { NSB } from "../../../services/NehonixSecurityBooster.service";
import NDS from "../../../services/NehonixDec.service";
import { ncu } from "../../../utils/NehonixCoreUtils";
import { NehonixShieldContext } from "../context/REACT.ShieldContext";
import {
  DomProcessorConfig,
  DomProcessorStats,
  ElementScanResult,
  DomProcessorContextT,
} from "../../types/frameworks.type";
import { MaliciousPatternResult } from "../../../services/MaliciousPatterns.service";

// Create context for the DOM processor
export const NehonixDomProcessorContext =
  React.createContext<DomProcessorContextT | null>(null);

// Hook to use the DOM processor context
export const useNehonixDomProcessor = () => {
  const context = useContext(NehonixDomProcessorContext);
  if (!context) {
    throw new Error(
      "useNehonixDomProcessor must be used within a NehonixDomProcessorProvider"
    );
  }
  return context;
};

// Default configuration for the DOM processor
const defaultConfig: DomProcessorConfig = {
  enabled: true,
  processingMode: "idle-callback", // 'idle-callback', 'worker', 'chunk'
  chunkSize: 50, // Number of elements to process in one chunk
  idleTimeout: 2000, // Timeout for requestIdleCallback
  throttleInterval: 1000, // Minimum time between scans
  targetElements: {
    a: true,
    script: true,
    iframe: true,
    img: true,
    form: true,
    input: true,
    button: true,
    source: true,
    embed: true,
    object: true,
  },
  attributesToScan: {
    href: true,
    src: true,
    action: true,
    formaction: true,
    data: true,
    onclick: true,
    onload: true,
    onerror: true,
    style: true,
  },
  scanDepth: "medium", // "light", "medium", "deep"
  ignoreInlineContent: false,
  scanShadowDOM: true,
  ignoreHiddenElements: true,
  parseCss: true,
  detectObfuscation: true,
  iframeSandboxPolicy: "strict", // "strict", "moderate", "permissive"
  scanXSS: true,
  scanCSRF: true,
  scanClickjacking: true,
  whitelistedDomains: [],
  blacklistedPatterns: [],
  onDetectionCallbacks: {},
  analyzeOptions: {
    debug: false,
    checkEncoding: true,
    ignoreCase: true,
    maxEncodingLayers: 3,
  },
};

// Initial stats state
const initialStats: DomProcessorStats = {
  elementsScanned: 0,
  threatsDetected: 0,
  lastScanTimestamp: 0,
  scanDuration: 0,
  scanningActive: false,
  elementTypeStats: {},
  threatsByType: {},
  blockedElements: [],
  pendingElements: 0,
  avgProcessingTimePerElement: 0,
  totalProcessingTime: 0,
};

/**
 * Nehonix DOM Processor Provider
 * Enhances NehonixShield with advanced DOM scanning capabilities
 */
export const NehonixDomProcessorProvider: React.FC<{
  children: React.ReactNode;
  initialConfig?: Partial<DomProcessorConfig>;
}> = ({ children, initialConfig = {} }) => {
  // Access the shield context
  const shieldContext = useContext(NehonixShieldContext);

  // Merge the default config with the provided initialConfig
  const [config, setConfig] = useState<DomProcessorConfig>({
    ...defaultConfig,
    ...initialConfig,
  });

  // Stats for the DOM processor
  const [stats, setStats] = useState<DomProcessorStats>(initialStats);

  // Queue of elements to be processed
  const processingQueue = useRef<Element[]>([]);

  // Flag for processing status
  const isProcessing = useRef<boolean>(false);

  // Worker reference
  const worker = useRef<Worker | null>(null);

  // Timer reference for throttling
  const throttleTimer = useRef<NodeJS.Timeout | null>(null);

  // Config reference for access in callbacks
  const configRef = useRef(config);

  // Update the config ref when config changes
  useEffect(() => {
    configRef.current = config;
  }, [config]);

  /**
   * Update the DOM processor configuration
   */
  const updateConfig = (newConfig: Partial<DomProcessorConfig>) => {
    setConfig((prevConfig) => {
      const updatedConfig = {
        ...prevConfig,
        ...newConfig,
        targetElements: {
          ...prevConfig.targetElements,
          ...(newConfig.targetElements || {}),
        },
        attributesToScan: {
          ...prevConfig.attributesToScan,
          ...(newConfig.attributesToScan || {}),
        },
        onDetectionCallbacks: {
          ...prevConfig.onDetectionCallbacks,
          ...(newConfig.onDetectionCallbacks || {}),
        },
      };
      return updatedConfig;
    });
  };

  /**
   * Scan a single DOM element for security threats
   */
  const scanElement = async (element: Element): Promise<ElementScanResult> => {
    const startTime = performance.now();
    const results: MaliciousPatternResult[] = [];
    const elementType = element.tagName.toLowerCase();
    const scannedAttributes: Record<string, MaliciousPatternResult> = {};

    try {
      // Check if this element type should be scanned
      if (
        !configRef.current.targetElements[
          elementType as keyof typeof configRef.current.targetElements
        ]
      ) {
        return {
          element,
          elementType,
          results: [],
          scannedAttributes: {},
          duration: performance.now() - startTime,
          timestamp: Date.now(),
          hasMaliciousContent: false,
        };
      }

      // Check if element is hidden and we should ignore hidden elements
      if (configRef.current.ignoreHiddenElements) {
        const computedStyle = window.getComputedStyle(element);
        if (
          computedStyle.display === "none" ||
          computedStyle.visibility === "hidden"
        ) {
          return {
            element,
            elementType,
            results: [],
            scannedAttributes: {},
            duration: performance.now() - startTime,
            timestamp: Date.now(),
            hasMaliciousContent: false,
          };
        }
      }

      // Scan relevant attributes
      for (const attrName in configRef.current.attributesToScan) {
        if (
          configRef.current.attributesToScan[
            attrName as keyof typeof configRef.current.attributesToScan
          ]
        ) {
          const attrValue = element.getAttribute(attrName);

          if (attrValue) {
            // Skip whitelisted domains
            if (attrName === "href" || attrName === "src") {
              const isWhitelisted = configRef.current.whitelistedDomains.some(
                (domain) => attrValue.includes(domain)
              );

              if (isWhitelisted) continue;
            }

            try {
              // Decode and normalize the attribute value
              const norm = await NDS.asyncDecodeAnyToPlainText(attrValue);
              const decodedValue = norm.val();
              const normalizedValue = decodedValue.normalize("NFC");

              // Analyze the attribute value
              const analysisResult = await NSB.analyzeUrl(
                normalizedValue,
                configRef.current.analyzeOptions
              );

              scannedAttributes[attrName] = analysisResult;

              if (analysisResult.isMalicious) {
                results.push(analysisResult);
              }
            } catch (error) {
              console.error(`Error scanning attribute ${attrName}:`, error);
            }
          }
        }
      }

      // Check for inline JavaScript if not ignored
      if (
        !configRef.current.ignoreInlineContent &&
        elementType === "script" &&
        !element.getAttribute("src")
      ) {
        try {
          const scriptContent = element.textContent || "";
          if (scriptContent.trim()) {
            // Create a mock URL with the script content for analysis
            const mockUrl = `http://mock.nehonix.space?script=${encodeURIComponent(
              scriptContent.substring(0, 2000)
            )}`;

            const norm = await NDS.asyncDecodeAnyToPlainText(mockUrl);
            const mockUrlDecoded = norm.val();
            const mockUrlNormalized = mockUrlDecoded.normalize("NFC");

            const scriptAnalysis = await NSB.analyzeUrl(
              mockUrlNormalized,
              configRef.current.analyzeOptions
            );

            scannedAttributes["inline-script"] = scriptAnalysis;

            if (scriptAnalysis.isMalicious) {
              results.push(scriptAnalysis);
            }
          }
        } catch (error) {
          console.error("Error scanning inline script:", error);
        }
      }

      // Handle CSS if enabled
      if (configRef.current.parseCss && elementType === "style") {
        try {
          const cssContent = element.textContent || "";
          if (cssContent.trim()) {
            // Scan for CSS injection attacks
            const mockUrl = `http://mock.nehonix.space?css=${encodeURIComponent(
              cssContent.substring(0, 2000)
            )}`;

            const norm = await NDS.asyncDecodeAnyToPlainText(mockUrl);
            const mockUrlDecoded = norm.val();
            const mockUrlNormalized = mockUrlDecoded.normalize("NFC");

            const cssAnalysis = await NSB.analyzeUrl(
              mockUrlNormalized,
              configRef.current.analyzeOptions
            );

            scannedAttributes["inline-css"] = cssAnalysis;

            if (cssAnalysis.isMalicious) {
              results.push(cssAnalysis);
            }
          }
        } catch (error) {
          console.error("Error scanning inline CSS:", error);
        }
      }

      // Scan Shadow DOM if enabled
      if (configRef.current.scanShadowDOM && element.shadowRoot) {
        try {
          const shadowElements = Array.from(
            element.shadowRoot.querySelectorAll("*")
          );
          for (const shadowEl of shadowElements) {
            // Add shadow DOM elements to the processing queue
            processingQueue.current.push(shadowEl);
          }
        } catch (error) {
          console.error("Error processing shadow DOM:", error);
        }
      }

      // Calculate if element has malicious content
      const hasMaliciousContent = results.length > 0;

      // Trigger callback for this element type if there's malicious content
      if (
        hasMaliciousContent &&
        configRef.current.onDetectionCallbacks[elementType]
      ) {
        configRef.current.onDetectionCallbacks[elementType]({
          element,
          results,
          elementType,
        });
      }

      return {
        element,
        elementType,
        results,
        scannedAttributes,
        duration: performance.now() - startTime,
        timestamp: Date.now(),
        hasMaliciousContent,
      };
    } catch (error) {
      console.error(`Error scanning element ${elementType}:`, error);
      return {
        element,
        elementType,
        results: [],
        scannedAttributes: {},
        duration: performance.now() - startTime,
        timestamp: Date.now(),
        hasMaliciousContent: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  };

  /**
   * Process chunks of elements from the queue
   */
  const processElementChunk = async () => {
    if (
      !isProcessing.current ||
      processingQueue.current.length === 0 ||
      !configRef.current.enabled
    ) {
      isProcessing.current = false;
      return;
    }

    const startTime = performance.now();
    const chunkSize = Math.min(
      configRef.current.chunkSize,
      processingQueue.current.length
    );
    const elementsToProcess = processingQueue.current.splice(0, chunkSize);

    setStats((prevStats) => ({
      ...prevStats,
      pendingElements: processingQueue.current.length,
    }));

    try {
      const scanPromises = elementsToProcess.map(scanElement);
      const results = await Promise.all(scanPromises);

      // Update stats with the scan results
      setStats((prevStats) => {
        const newElementTypeStats = { ...prevStats.elementTypeStats };
        const newThreatsByType = { ...prevStats.threatsByType };
        const newBlockedElements = [...prevStats.blockedElements];

        let newThreatsDetected = prevStats.threatsDetected;

        // Process each result
        results.forEach((result) => {
          // Update element type stats
          newElementTypeStats[result.elementType] =
            (newElementTypeStats[result.elementType] || 0) + 1;

          // Process detected threats
          if (result.hasMaliciousContent) {
            newThreatsDetected++;

            // Add to blocked elements if there are threats
            newBlockedElements.push({
              elementType: result.elementType,
              timestamp: result.timestamp,
              threatTypes: result.results
                .map((r) => r.detectedPatterns.map((p) => p.type))
                .flatMap((x) => x),
            });

            // Update threats by type stats
            result.results.forEach((threat, i) => {
              const type = threat.detectedPatterns.map((x) => x.type)[i];
              newThreatsByType[type] = (newThreatsByType[type] || 0) + 1;
            });
          }
        });

        // Calculate new processing time metrics
        const processingTime = performance.now() - startTime;
        const totalProcessingTime =
          prevStats.totalProcessingTime + processingTime;
        const elementsScanned =
          prevStats.elementsScanned + elementsToProcess.length;

        return {
          ...prevStats,
          elementsScanned,
          threatsDetected: newThreatsDetected,
          lastScanTimestamp: Date.now(),
          scanDuration: processingTime,
          elementTypeStats: newElementTypeStats,
          threatsByType: newThreatsByType,
          blockedElements: newBlockedElements,
          totalProcessingTime,
          avgProcessingTimePerElement: totalProcessingTime / elementsScanned,
        };
      });

      // Continue processing if there are more elements in the queue
      if (processingQueue.current.length > 0) {
        scheduleNextChunk();
      } else {
        isProcessing.current = false;
        setStats((prev) => ({ ...prev, scanningActive: false }));
      }
    } catch (error) {
      console.error("Error processing element chunk:", error);
      isProcessing.current = false;
      setStats((prev) => ({ ...prev, scanningActive: false }));
    }
  };

  /**
   * Schedule the next chunk of processing based on the configured mode
   */
  const scheduleNextChunk = useCallback(() => {
    switch (configRef.current.processingMode) {
      case "idle-callback":
        if ("requestIdleCallback" in window) {
          window.requestIdleCallback(
            () => {
              processElementChunk();
            },
            { timeout: configRef.current.idleTimeout }
          );
        } else {
          // Fallback for browsers that don't support requestIdleCallback
          setTimeout(processElementChunk, 1);
        }
        break;

      case "chunk":
        setTimeout(processElementChunk, 1);
        break;

      case "worker":
        // If worker mode is enabled but no worker is available, fallback to chunk mode
        if (!worker.current) {
          setTimeout(processElementChunk, 1);
        }
        break;
    }
  }, []);

  /**
   * Start a new DOM scan - this is the main function to initiate scanning
   */
  const scanDOM = useCallback(() => {
    // If already processing or disabled, don't start a new scan
    if (isProcessing.current || !configRef.current.enabled) {
      return;
    }

    // Check if we should throttle this scan
    if (throttleTimer.current) {
      return;
    }

    // Set up throttling
    throttleTimer.current = setTimeout(() => {
      throttleTimer.current = null;
    }, configRef.current.throttleInterval);

    // Clear previous queue and set processing flag
    processingQueue.current = [];
    isProcessing.current = true;

    setStats((prev) => ({
      ...prev,
      scanningActive: true,
      pendingElements: 0,
    }));

    // Collect all relevant elements from the DOM
    let selector = "";
    Object.keys(configRef.current.targetElements).forEach((tag, index) => {
      if (
        configRef.current.targetElements[
          tag as keyof typeof configRef.current.targetElements
        ]
      ) {
        selector += index > 0 ? `, ${tag}` : tag;
      }
    });

    if (selector) {
      const elements = Array.from(document.querySelectorAll(selector));
      processingQueue.current = elements;

      setStats((prev) => ({
        ...prev,
        pendingElements: elements.length,
      }));

      // Start processing the queue
      scheduleNextChunk();
    } else {
      isProcessing.current = false;
      setStats((prev) => ({ ...prev, scanningActive: false }));
    }
  }, [scheduleNextChunk]);

  /**
   * Initialize a web worker if worker mode is enabled
   */
  const initializeWorker = useCallback(() => {
    if (
      configRef.current.processingMode === "worker" &&
      typeof Worker !== "undefined"
    ) {
      // This is a sample implementation - in a real system, you'd need to create a proper worker file
      const workerCode = `
        self.onmessage = function(e) {
          // Worker would implement element scanning logic here
          // For now, just send back the received elements
          self.postMessage({
            type: 'scan-results',
            results: e.data.elements.map(el => ({
              elementId: el.id,
              processed: true
            }))
          });
        }
      `;

      try {
        const blob = new Blob([workerCode], { type: "application/javascript" });
        const workerUrl = URL.createObjectURL(blob);
        worker.current = new Worker(workerUrl);

        worker.current.onmessage = (e) => {
          // Handle worker messages here
          if (e.data.type === "scan-results") {
            // Process scan results from worker
            console.log("Received worker results:", e.data.results);
          }
        };

        worker.current.onerror = (error) => {
          console.error("Worker error:", error);
          // Fallback to non-worker mode
          configRef.current.processingMode = "chunk";
        };
      } catch (error) {
        console.error("Failed to initialize worker:", error);
        // Fallback to chunk mode
        configRef.current.processingMode = "chunk";
      }
    }
  }, []);

  /**
   * Clean up worker when component unmounts
   */
  const cleanupWorker = useCallback(() => {
    if (worker.current) {
      worker.current.terminate();
      worker.current = null;
    }
  }, []);

  /**
   * Reset all processing stats
   */
  const resetStats = useCallback(() => {
    setStats(initialStats);
  }, []);

  /**
   * Stop all ongoing scans
   */
  const stopScanning = useCallback(() => {
    isProcessing.current = false;
    processingQueue.current = [];
    setStats((prev) => ({
      ...prev,
      scanningActive: false,
      pendingElements: 0,
    }));
  }, []);

  /**
   * Get detailed report about scanning activity
   */
  const getSecurityReport = useCallback(() => {
    return {
      ...stats,
      config: configRef.current,
      timestamp: Date.now(),
      topThreats: Object.entries(stats.threatsByType)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5),
      mostScannedElements: Object.entries(stats.elementTypeStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5),
      scanEfficiency: {
        elementsPerSecond: stats.avgProcessingTimePerElement
          ? 1000 / stats.avgProcessingTimePerElement
          : 0,
        threatsPerElement: stats.elementsScanned
          ? stats.threatsDetected / stats.elementsScanned
          : 0,
      },
    };
  }, [stats]);

  // Set up mutation observer to detect DOM changes
  useEffect(() => {
    if (!configRef.current.enabled) return;

    // Initialize worker if needed
    if (configRef.current.processingMode === "worker") {
      initializeWorker();
    }

    // Create a mutation observer to detect DOM changes
    const observer = new MutationObserver((mutations) => {
      let needsScan = false;

      for (const mutation of mutations) {
        if (mutation.type === "childList" && mutation.addedNodes.length > 0) {
          needsScan = true;
          break;
        }
      }

      if (needsScan && configRef.current.enabled) {
        // Don't scan immediately, but queue it up for the next throttle cycle
        if (!throttleTimer.current) {
          throttleTimer.current = setTimeout(() => {
            throttleTimer.current = null;
            scanDOM();
          }, configRef.current.throttleInterval);
        }
      }
    });

    // Start observing DOM changes
    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });

    // Perform initial scan
    scanDOM();

    // Cleanup function
    return () => {
      observer.disconnect();
      cleanupWorker();
      stopScanning();

      if (throttleTimer.current) {
        clearTimeout(throttleTimer.current);
        throttleTimer.current = null;
      }
    };
  }, [scanDOM, initializeWorker, cleanupWorker, stopScanning]);

  // Provide context value
  const contextValue: DomProcessorContextT = {
    config,
    updateConfig,
    stats,
    scanDOM,
    stopScanning,
    resetStats,
    getSecurityReport,
    isScanning: stats.scanningActive,
  };

  return (
    <NehonixDomProcessorContext.Provider value={contextValue}>
      {children}
    </NehonixDomProcessorContext.Provider>
  );
};

/**
 * Hook to combine NehonixShield and DomProcessor functionality
 */
export const useNehonixSecurityPlugging = () => {
  const shield = useContext(NehonixShieldContext);
  const domProcessor = useContext(NehonixDomProcessorContext);

  if (!shield) {
    throw new Error(
      "useNehonixSecuritySuite must be used within a NehonixShieldProvider"
    );
  }

  if (!domProcessor) {
    throw new Error(
      "useNehonixSecuritySuite must be used within a NehonixDomProcessorProvider"
    );
  }

  // Force scan in both systems
  const forceFullScan = useCallback(() => {
    shield.forceScan();
    domProcessor.scanDOM();
  }, [shield, domProcessor]);

  // Reset all stats and results
  const resetAllStats = useCallback(() => {
    shield.clearResults();
    domProcessor.resetStats();
  }, [shield, domProcessor]);

  // Get comprehensive security report combining both systems
  const getComprehensiveReport = useCallback(() => {
    return {
      shield: {
        config: shield.config,
        results: shield.analysisResults,
      },
      domProcessor: domProcessor.getSecurityReport(),
      timestamp: Date.now(),
      summary: {
        totalThreatsDetected:
          shield.analysisResults.totalBlocked +
          domProcessor.stats.threatsDetected,
        isActive:
          shield.config.enableBackgroundScanning && domProcessor.config.enabled,
        lastScanTime: Math.max(
          shield.analysisResults.lastScanTimestamp,
          domProcessor.stats.lastScanTimestamp
        ),
      },
    };
  }, [shield, domProcessor]);

  return {
    shield,
    domProcessor,
    forceFullScan,
    resetAllStats,
    getComprehensiveReport,
    isScanning: shield.isScanning || domProcessor.stats.scanningActive,
  };
};
