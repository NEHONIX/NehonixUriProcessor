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
import {
  MaliciousPatternResult,
  MaliciousPatternType,
} from "../../../services/MaliciousPatterns.service";

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

// Utility to map string confidence to numeric value
const mapConfidenceToNumber = (
  confidence: "low" | "medium" | "high"
): number => {
  switch (confidence) {
    case "low":
      return 0.3;
    case "medium":
      return 0.6;
    case "high":
      return 0.9;
    default:
      return 0;
  }
};

// Utility to generate a CSS selector path for an element
const getDomPath = (element: Element): string => {
  if (!element.parentElement) return element.tagName.toLowerCase();
  const pathParts: string[] = [];
  let current: Element | null = element;

  while (current && current.tagName) {
    let selector = current.tagName.toLowerCase();
    if (current.id) {
      selector = `#${current.id}`;
      pathParts.unshift(selector);
      break;
    }
    if (current.className && typeof current.className === "string") {
      const classes = current.className.trim().split(/\s+/).join(".");
      if (classes) selector += `.${classes}`;
    }
    pathParts.unshift(selector);
    current = current.parentElement;
  }

  return pathParts.join(" > ");
};

// Default configuration for the DOM processor
const defaultConfig: DomProcessorConfig = {
  enabled: true,
  processingMode: "idle-callback",
  chunkSize: 50,
  idleTimeout: 2000,
  throttleInterval: 1000,
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
  scanDepth: "medium",
  ignoreInlineContent: false,
  scanShadowDOM: true,
  ignoreHiddenElements: true,
  parseCss: true,
  detectObfuscation: true,
  iframeSandboxPolicy: "strict",
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
  enableThreatIntelligence: false,
  adaptiveChunkSize: true,
  threatIntelligenceApiKey:
    // process.env.REACT_NEHONIX_DOM_PROCESSOR_PUBLIC_API_KEY ||
    "AIzaSyAj46be9NZBVkFxD2FujgaoBD2GyrLA5z4", //public api 'REACT_NEHONIX_DOM_PROCESSOR_PUBLIC_API_KEY': AIzaSyAj46be9NZBVkFxD2FujgaoBD2GyrLA5z4
  detailedLogging: true,
  confidenceThreshold: 0.7,
  urlUtils: { dynamicWhitelist: [] },
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
  const shieldContext = useContext(NehonixShieldContext);
  const [config, setConfig] = useState<DomProcessorConfig>({
    ...defaultConfig,
    ...initialConfig,
  });
  const [stats, setStats] = useState<DomProcessorStats>(initialStats);
  const processingQueue = useRef<Element[]>([]);
  const isProcessing = useRef<boolean>(false);
  const worker = useRef<Worker | null>(null);
  const throttleTimer = useRef<NodeJS.Timeout | null>(null);
  const configRef = useRef(config);

  useEffect(() => {
    configRef.current = config;
  }, [config]);

  const checkWithThreatIntelligence = async (url: string): Promise<boolean> => {
    if (
      !configRef.current.enableThreatIntelligence ||
      !configRef.current.threatIntelligenceApiKey
    ) {
      return false;
    }

    try {
      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${configRef.current.threatIntelligenceApiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: { clientId: "nehonix", clientVersion: "2.1.2" },
            threatInfo: {
              threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
              ],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url }],
            },
          }),
        }
      );
      const data = await response.json();
      return !!data.matches?.length;
    } catch (error) {
      console.error("Threat intelligence check failed:", error);
      return false;
    }
  };

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
        urlUtils: {
          ...prevConfig.urlUtils,
          ...(newConfig.urlUtils || {}),
        },
      };
      return updatedConfig;
    });
  };

  const addToDynamicWhitelist = (url: string) => {
    setConfig((prev) => ({
      ...prev,
      urlUtils: {
        ...prev.urlUtils,
        dynamicWhitelist: [...(prev.urlUtils?.dynamicWhitelist || []), url],
      },
    }));
  };

  const scanElement = async (element: Element): Promise<ElementScanResult> => {
    const startTime = performance.now();
    const results: MaliciousPatternResult[] = [];
    const elementType = element.tagName.toLowerCase();
    const scannedAttributes: Record<string, MaliciousPatternResult> = {};

    // Collect metadata for debugging
    const metadata: ElementScanResult["metadata"] = {
      domLocation:
        element.outerHTML.length > 500
          ? element.outerHTML.substring(0, 500) + "..."
          : element.outerHTML,
      elementId: element.id || undefined,
      className: element.className || undefined,
      parentElement: element.parentElement
        ? {
            tagName: element.parentElement.tagName.toLowerCase(),
            id: element.parentElement.id || undefined,
            className: element.parentElement.className || undefined,
          }
        : undefined,
      domPath: getDomPath(element),
      innerTextSnippet:
        element.textContent && element.textContent.length > 100
          ? element.textContent.substring(0, 100) + "..."
          : element.textContent || undefined,
      attributes: Array.from(element.attributes).reduce(
        (acc, attr) => ({
          ...acc,
          [attr.name]: attr.value,
        }),
        {} as Record<string, string>
      ),
    };

    try {
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
          metadata,
        };
      }

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
            metadata,
          };
        }
      }

      for (const attrName in configRef.current.attributesToScan) {
        if (
          configRef.current.attributesToScan[
            attrName as keyof typeof configRef.current.attributesToScan
          ]
        ) {
          const attrValue = element.getAttribute(attrName);

          if (attrValue) {
            if (attrName === "href" || attrName === "src") {
              const isWhitelisted =
                configRef.current.whitelistedDomains.some((domain) =>
                  attrValue.includes(domain)
                ) ||
                configRef.current.urlUtils?.dynamicWhitelist?.includes(
                  attrValue
                );

              if (isWhitelisted) continue;
            }

            if (
              (attrName === "href" || attrName === "src") &&
              (await checkWithThreatIntelligence(attrValue))
            ) {
              const threatResult: MaliciousPatternResult = {
                isMalicious: true,
                score: 0.9,
                recommendation: "Block or sanitize the malicious URL",
                detectedPatterns: [
                  {
                    type: MaliciousPatternType.KNOWN_MALICIOUS_URL,
                    pattern: attrValue,
                    location: `${elementType}[${attrName}]`,
                    severity: "high",
                    confidence: "high",
                    description:
                      "URL identified as malicious by threat intelligence",
                    matchedValue: attrValue,
                    contextScore: 0.9,
                  },
                ],
                confidence: "high",
              };
              results.push(threatResult);
              scannedAttributes[attrName] = threatResult;
              continue;
            }

            try {
              const norm = await NDS.asyncDecodeAnyToPlainText(attrValue);
              const decodedValue = norm.val();
              const normalizedValue = decodedValue.normalize("NFC");

              const analysisResult = await NSB.analyzeUrl(
                normalizedValue,
                configRef.current.analyzeOptions
              );

              if (
                configRef.current.detailedLogging &&
                analysisResult.isMalicious
              ) {
                console.log(`Threat detected in ${elementType}.${attrName}:`, {
                  value: attrValue,
                  decoded: normalizedValue,
                  patterns: analysisResult.detectedPatterns,
                  confidence: analysisResult.confidence,
                  metadata,
                });
              }

              scannedAttributes[attrName] = analysisResult;

              if (
                analysisResult.isMalicious &&
                mapConfidenceToNumber(analysisResult.confidence) >=
                  configRef.current.confidenceThreshold
              ) {
                results.push(analysisResult);
              } else if (analysisResult.isMalicious) {
                console.warn("Low-confidence threat detected:", analysisResult);
              }
            } catch (error) {
              console.error(`Error scanning attribute ${attrName}:`, error);
            }
          }
        }
      }

      if (
        !configRef.current.ignoreInlineContent &&
        elementType === "script" &&
        !element.getAttribute("src")
      ) {
        try {
          const scriptContent = element.textContent || "";
          if (scriptContent.trim()) {
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

            if (
              configRef.current.detailedLogging &&
              scriptAnalysis.isMalicious
            ) {
              console.log(`Threat detected in ${elementType}.inline-script:`, {
                content: scriptContent.substring(0, 200),
                patterns: scriptAnalysis.detectedPatterns,
                confidence: scriptAnalysis.confidence,
                metadata,
              });
            }

            scannedAttributes["inline-script"] = scriptAnalysis;

            if (
              scriptAnalysis.isMalicious &&
              mapConfidenceToNumber(scriptAnalysis.confidence) >=
                configRef.current.confidenceThreshold
            ) {
              results.push(scriptAnalysis);
            }
          }
        } catch (error) {
          console.error("Error scanning inline script:", error);
        }
      }

      if (configRef.current.parseCss && elementType === "style") {
        try {
          const cssContent = element.textContent || "";
          if (cssContent.trim()) {
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

            if (configRef.current.detailedLogging && cssAnalysis.isMalicious) {
              console.log(`Threat detected in ${elementType}.inline-css:`, {
                content: cssContent.substring(0, 200),
                patterns: cssAnalysis.detectedPatterns,
                confidence: cssAnalysis.confidence,
                metadata,
              });
            }

            scannedAttributes["inline-css"] = cssAnalysis;

            if (
              cssAnalysis.isMalicious &&
              mapConfidenceToNumber(cssAnalysis.confidence) >=
                configRef.current.confidenceThreshold
            ) {
              results.push(cssAnalysis);
            }
          }
        } catch (error) {
          console.error("Error scanning inline CSS:", error);
        }
      }

      if (configRef.current.scanShadowDOM && element.shadowRoot) {
        try {
          const shadowElements = Array.from(
            element.shadowRoot.querySelectorAll("*")
          );
          for (const shadowEl of shadowElements) {
            processingQueue.current.push(shadowEl);
          }
        } catch (error) {
          console.error("Error processing shadow DOM:", error);
        }
      }

      const hasMaliciousContent = results.length > 0;

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
        metadata,
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
        metadata,
      };
    }
  };

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
    let chunkSize = configRef.current.chunkSize;
    if (configRef.current.adaptiveChunkSize) {
      chunkSize = Math.min(
        processingQueue.current.length,
        Math.max(
          10,
          Math.floor(100 / (document.readyState === "complete" ? 1 : 2))
        )
      );
    }
    const elementsToProcess = processingQueue.current.splice(0, chunkSize);

    setStats((prevStats) => ({
      ...prevStats,
      pendingElements: processingQueue.current.length,
    }));

    try {
      const scanPromises = elementsToProcess.map(scanElement);
      const results = await Promise.all(scanPromises);

      setStats((prevStats) => {
        const newElementTypeStats = { ...prevStats.elementTypeStats };
        const newThreatsByType = { ...prevStats.threatsByType };
        const newBlockedElements = [...prevStats.blockedElements];

        let newThreatsDetected = prevStats.threatsDetected;

        results.forEach((result) => {
          newElementTypeStats[result.elementType] =
            (newElementTypeStats[result.elementType] || 0) + 1;

          if (result.hasMaliciousContent) {
            newThreatsDetected++;

            newBlockedElements.push({
              elementType: result.elementType,
              timestamp: result.timestamp,
              threatTypes: result.results
                .map((r) => r.detectedPatterns.map((p) => p.type))
                .flatMap((x) => x),
              metadata: result.metadata, // Include metadata in blockedElements
            });

            result.results.forEach((threat) => {
              threat.detectedPatterns.forEach((pattern) => {
                newThreatsByType[pattern.type] =
                  (newThreatsByType[pattern.type] || 0) + 1;
              });
            });
          }
        });

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
          setTimeout(processElementChunk, 1);
        }
        break;

      case "chunk":
        setTimeout(processElementChunk, 1);
        break;

      case "worker":
        if (!worker.current) {
          setTimeout(processElementChunk, 1);
        }
        break;
    }
  }, []);

  const scanDOM = useCallback(() => {
    if (isProcessing.current || !configRef.current.enabled) {
      return;
    }

    if (throttleTimer.current) {
      return;
    }

    throttleTimer.current = setTimeout(() => {
      throttleTimer.current = null;
    }, configRef.current.throttleInterval);

    processingQueue.current = [];
    isProcessing.current = true;

    setStats((prev) => ({
      ...prev,
      scanningActive: true,
      pendingElements: 0,
    }));

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

      scheduleNextChunk();
    } else {
      isProcessing.current = false;
      setStats((prev) => ({ ...prev, scanningActive: false }));
    }
  }, [scheduleNextChunk]);

  const initializeWorker = useCallback(() => {
    if (
      configRef.current.processingMode === "worker" &&
      typeof Worker !== "undefined"
    ) {
      const workerCode = `
        self.onmessage = function(e) {
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
          if (e.data.type === "scan-results") {
            console.log("Received worker results:", e.data.results);
          }
        };

        worker.current.onerror = (error) => {
          console.error("Worker error:", error);
          configRef.current.processingMode = "chunk";
        };
      } catch (error) {
        console.error("Failed to initialize worker:", error);
        configRef.current.processingMode = "chunk";
      }
    }
  }, []);

  const cleanupWorker = useCallback(() => {
    if (worker.current) {
      worker.current.terminate();
      worker.current = null;
    }
  }, []);

  const resetStats = useCallback(() => {
    setStats(initialStats);
  }, []);

  const stopScanning = useCallback(() => {
    isProcessing.current = false;
    processingQueue.current = [];
    setStats((prev) => ({
      ...prev,
      scanningActive: false,
      pendingElements: 0,
    }));
  }, []);

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

  useEffect(() => {
    if (!configRef.current.enabled) return;

    if (configRef.current.processingMode === "worker") {
      initializeWorker();
    }

    const observer = new MutationObserver((mutations) => {
      let needsScan = false;

      for (const mutation of mutations) {
        if (mutation.type === "childList" && mutation.addedNodes.length > 0) {
          needsScan = true;
          break;
        }
      }

      if (needsScan && configRef.current.enabled) {
        if (!throttleTimer.current) {
          throttleTimer.current = setTimeout(() => {
            throttleTimer.current = null;
            scanDOM();
          }, configRef.current.throttleInterval);
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });

    scanDOM();

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

  const contextValue: DomProcessorContextT = {
    config,
    updateConfig,
    stats,
    scanDOM,
    stopScanning,
    resetStats,
    getSecurityReport,
    isScanning: stats.scanningActive,
    addToDynamicWhitelist,
  };

  return (
    <NehonixDomProcessorContext.Provider value={contextValue}>
      {children}
    </NehonixDomProcessorContext.Provider>
  );
};
