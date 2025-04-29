import React, {
  createContext,
  useCallback,
  useEffect,
  useState,
  useRef,
} from "react";
import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
  DetectedPattern,
} from "../../services/MaliciousPatterns.service";
import { NSB } from "../../services/NehonixSecurityBooster.service";
import { AlertProps, DomAnalysisResult, EnhancedShieldContextType, EnhancedShieldOptions, EnhancedShieldProviderProps, ShieldContextType } from "./provider.type";
import SecurityAlert from "./REACT.SecurityAlert";

const defaultEnhancedOptions: EnhancedShieldOptions = {
  blockOnMalicious: false,
  blockThreshold: 80,
  showAlerts: true,
  alertDuration: 5000,
  scanDom: true,
  scanRequests: true,
  deepScan: false,
  whitelistedDomains: [],
  alertPosition: "top-right",
  autoCleanDOM: false,
  scanInterval: 5000,
  reportToServer: false,
};


// Create enhanced context
export const NehonixShieldContext = createContext<
  EnhancedShieldContextType | undefined
>(undefined);

/**
 * Enhanced Shield Provider component
 */
export const NehonixShieldProvider: React.FC<
  EnhancedShieldProviderProps
> = ({ children, options: initialOptions = {} }) => {
  // Merge with defaults
  const [options, setOptions] = useState<EnhancedShieldOptions>({
    ...defaultEnhancedOptions,
    ...initialOptions,
  });

  // State for tracking
  const [maliciousElements, setMaliciousElements] = useState<
    DomAnalysisResult[]
  >([]);
  const [blockedRequests, setBlockedRequests] = useState<string[]>([]);
  const [alerts, setAlerts] = useState<
    Array<{
      id: string;
      message: string;
      type: "warning" | "error" | "info";
      details?: DetectedPattern[];
    }>
  >([]);

  // Refs
  const requestInterceptorRef = useRef<any>(null);
  const intervalRef = useRef<number | null>(null);
  const originalFetch = useRef<typeof window.fetch | null>(null);
  const originalXHR = useRef<any>(null);

  // Base methods from original shield
  const analyzeUrl = useCallback(
    async (url: string, customOptions: MaliciousPatternOptions = {}) => {
      const mergedOptions = { ...options, ...customOptions };
      return await NSB.analyzeUrl(url, mergedOptions);
    },
    [options]
  );

  const scanInput = useCallback(
    async (input: string, customOptions: MaliciousPatternOptions = {}) => {
      const mergedOptions = { ...options, ...customOptions };
      const url = "http://mock.nehonix.space?q=";
      return await NSB.analyzeUrl(
        url + encodeURIComponent(input),
        mergedOptions
      );
    },
    [options]
  );

  const provideFeedback = useCallback(
    (url: string, result: MaliciousPatternResult, isCorrect: boolean) => {
      NSB.provideFeedback(url, result, isCorrect, "user_reported");
    },
    []
  );

  const getPerformanceMetrics = useCallback(() => {
    return NSB.getPerformanceMetrics();
  }, []);

  // Show an alert
  const showAlert = useCallback(
    (
      message: string,
      type: "warning" | "error" | "info",
      details?: DetectedPattern[]
    ) => {
      if (!options.showAlerts) return;

      const id = Math.random().toString(36).substring(2, 9);
      setAlerts((prev) => [...prev, { id, message, type, details }]);

      setTimeout(() => {
        setAlerts((prev) => prev.filter((alert) => alert.id !== id));
      }, options.alertDuration);
    },
    [options.showAlerts, options.alertDuration]
  );

  // Clear all alerts
  const clearAlerts = useCallback(() => {
    setAlerts([]);
  }, []);

  // Reset tracking stats
  const resetStats = useCallback(() => {
    setMaliciousElements([]);
    setBlockedRequests([]);
  }, []);

  // Update shield options
  const setShieldOptions = useCallback(
    (newOptions: Partial<EnhancedShieldOptions>) => {
      setOptions((prev) => {
        const updated = { ...prev, ...newOptions };

        // Apply changes based on new options
        if (updated.scanDom && !prev.scanDom) {
          startDomScanning(updated);
        } else if (!updated.scanDom && prev.scanDom && intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }

        return updated;
      });
    },
    []
  );

  // Analyze DOM for potential threats
  const scanDom = useCallback(
    async (customOptions?: Partial<EnhancedShieldOptions>) => {
      const scanOptions = { ...options, ...customOptions };
      const results: DomAnalysisResult[] = [];

      // Get all elements with attributes
      const elements = document.querySelectorAll("*");

      for (let i = 0; i < elements.length; i++) {
        const element = elements[i] as HTMLElement;

        // Skip if element is part of Nehonix Shield UI
        if (element.closest(".nehonix-shield-ui")) continue;

        // Analyze each attribute
        const attributesToCheck = [
          "href",
          "src",
          "style",
          "onclick",
          "onload",
          "onerror",
        ];
        let elementResult: MaliciousPatternResult | null = null;

        for (const attr of attributesToCheck) {
          const value = element.getAttribute(attr);
          if (!value) continue;

          // Skip whitelisted domains
          if (attr === "href" || attr === "src") {
            try {
              const url = new URL(value, window.location.origin);
              if (
                scanOptions.whitelistedDomains.some((domain) =>
                  url.hostname.includes(domain)
                )
              ) {
                continue;
              }
            } catch (e) {
              // Invalid URL, continue with analysis
            }
          }

          // Analyze the attribute value
          const result = await scanInput(value, scanOptions);

          // If malicious and no previous malicious result for this element
          if (
            result.isMalicious &&
            (!elementResult || !elementResult.isMalicious)
          ) {
            elementResult = result;
          }
          // If both are malicious, combine with the higher score
          else if (
            result.isMalicious &&
            elementResult &&
            elementResult.isMalicious
          ) {
            elementResult =
              result.score > elementResult.score ? result : elementResult;
          }
        }

        // Deep scan: also check text content
        if (
          scanOptions.deepScan &&
          element.textContent &&
          !element.children.length
        ) {
          const text = element.textContent.trim();

          // Only analyze text that might be suspicious (contains script tags, iframe, etc.)
          const suspiciousPatterns = [
            "<script",
            "javascript:",
            "data:text/html",
            "<iframe",
            "eval(",
            "document.write",
            "fromCharCode",
            "String.fromCharCode",
          ];

          if (
            text.length > 0 &&
            suspiciousPatterns.some((pattern) =>
              text.toLowerCase().includes(pattern)
            )
          ) {
            const result = await scanInput(text, scanOptions);

            if (
              result.isMalicious &&
              (!elementResult || result.score > elementResult.score)
            ) {
              elementResult = result;
            }
          }
        }

        // If malicious content was found
        if (elementResult && elementResult.isMalicious) {
          results.push({ element, result: elementResult });

          // Auto-clean if enabled
          if (scanOptions.autoCleanDOM) {
            cleanElement(element, elementResult);
          }
        }
      }

      // Update state with new malicious elements
      if (results.length > 0) {
        setMaliciousElements((prev) => {
          // Deduplicate elements
          const existing = new Set(prev.map((item) => item.element));
          const newItems = results.filter(
            (item) => !existing.has(item.element)
          );

          if (newItems.length > 0 && scanOptions.showAlerts) {
            const highestThreat = newItems.reduce(
              (max, current) =>
                current.result.score > max.result.score ? current : max,
              newItems[0]
            );

            showAlert(
              `Detected ${newItems.length} malicious element(s) on this page`,
              highestThreat.result.score > scanOptions.blockThreshold
                ? "error"
                : "warning",
              highestThreat.result.detectedPatterns
            );
          }

          return [...prev, ...newItems];
        });
      }

      return results;
    },
    [options, scanInput, showAlert]
  );

  // Clean/sanitize malicious element
  const cleanElement = (
    element: HTMLElement,
    result: MaliciousPatternResult
  ) => {
    // For each detected pattern, try to clean the specific attribute
    result.detectedPatterns.forEach((pattern) => {
      // Extract attribute name from location if possible
      const attrMatch = pattern.location.match(/attribute:([a-zA-Z0-9-]+)/);

      if (attrMatch && attrMatch[1]) {
        const attribute = attrMatch[1];
        if (element.hasAttribute(attribute)) {
          // Remove the attribute or sanitize it
          element.removeAttribute(attribute);
        }
      } else if (pattern.location.includes("text")) {
        // If it's in text content, we replace it with a warning message
        element.textContent = "[Content removed by Nehonix Shield]";
      } else if (pattern.location.includes("innerHTML")) {
        // If it's in HTML content, we clear it
        element.innerHTML = "";
      }
    });
  };

  // Start periodic DOM scanning
  const startDomScanning = useCallback(
    (scanOptions: EnhancedShieldOptions) => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }

      // Initial scan
      scanDom(scanOptions);

      // Setup interval if interval is positive
      if (scanOptions.scanInterval > 0) {
        intervalRef.current = window.setInterval(() => {
          scanDom(scanOptions);
        }, scanOptions.scanInterval);
      }
    },
    [scanDom]
  );

  // Intercept and analyze network requests
  const interceptRequests = useCallback(
    (enable: boolean) => {
      // Remove existing interceptors if any
      if (requestInterceptorRef.current) {
        if (originalFetch.current) {
          window.fetch = originalFetch.current;
        }
        if (originalXHR.current) {
          window.XMLHttpRequest = originalXHR.current;
        }
        requestInterceptorRef.current = null;
      }

      if (!enable) return;

      // Store original methods
      originalFetch.current = window.fetch;
      originalXHR.current = window.XMLHttpRequest;

      // Intercept fetch
      window.fetch = async function (
        input: RequestInfo | URL,
        init?: RequestInit
      ) {
        const url =
          typeof input === "string"
            ? input
            : input instanceof URL
            ? input.href
            : input.url;

        try {
          // Skip analysis for whitelisted domains
          const parsedUrl = new URL(url, window.location.origin);
          if (
            options.whitelistedDomains.some((domain) =>
              parsedUrl.hostname.includes(domain)
            )
          ) {
            return originalFetch.current!(input, init);
          }

          // Analyze URL
          const result = await NSB.analyzeUrl(url, options);

          // If malicious and should block
          if (
            result.isMalicious &&
            options.blockOnMalicious &&
            result.score >= options.blockThreshold
          ) {
            setBlockedRequests((prev) => {
              const newBlocked = [...prev, url];
              if (!prev.includes(url)) {
                showAlert(
                  `Blocked malicious request to: ${new URL(url).hostname}`,
                  "error",
                  result.detectedPatterns
                );
              }
              return newBlocked;
            });

            // Mock a network error
            return Promise.reject(
              new Error("Request blocked by Nehonix Shield")
            );
          }

          // Otherwise, proceed with the original request
          return originalFetch.current!(input, init);
        } catch (error) {
          console.error("Error in Nehonix Shield fetch interceptor:", error);
          // If analysis fails, allow the request
          return originalFetch.current!(input, init);
        }
      };

      // Intercept XHR
      window.XMLHttpRequest = function () {
        const xhr = new originalXHR.current!();
        const originalOpen = xhr.open;

        xhr.open = function (
          method: string,
          url: string | URL,
          ...args: any[]
        ) {
          const urlString = url instanceof URL ? url.href : url;
          xhr._nehonixUrl = urlString;

          // Original open - we'll check before send
          originalOpen.call(xhr, method, url, ...args);
        };

        const originalSend = xhr.send;
        xhr.send = async function (body?: Document | BodyInit | null) {
          try {
            if (xhr._nehonixUrl) {
              // Skip analysis for whitelisted domains
              const parsedUrl = new URL(
                xhr._nehonixUrl,
                window.location.origin
              );
              if (
                options.whitelistedDomains.some((domain) =>
                  parsedUrl.hostname.includes(domain)
                )
              ) {
                originalSend.call(xhr, body);
                return;
              }

              // Analyze URL
              const result = await NSB.analyzeUrl(xhr._nehonixUrl, options);

              // Check body if in deep scan mode
              let bodyResult = null;
              if (options.deepScan && body && typeof body === "string") {
                bodyResult = await scanInput(body);
              }

              const finalResult =
                bodyResult &&
                bodyResult.isMalicious &&
                bodyResult.score > result.score
                  ? bodyResult
                  : result;

              // If malicious and should block
              if (
                finalResult.isMalicious &&
                options.blockOnMalicious &&
                finalResult.score >= options.blockThreshold
              ) {
                setBlockedRequests((prev) => {
                  const newBlocked = [...prev, xhr._nehonixUrl];
                  if (!prev.includes(xhr._nehonixUrl)) {
                    showAlert(
                      `Blocked malicious XHR request to: ${
                        new URL(xhr._nehonixUrl).hostname
                      }`,
                      "error",
                      finalResult.detectedPatterns
                    );
                  }
                  return newBlocked;
                });

                // Abort the request
                xhr.abort();
                return;
              }
            }

            // Otherwise, proceed with the original request
            originalSend.call(xhr, body);
          } catch (error) {
            console.error("Error in Nehonix Shield XHR interceptor:", error);
            // If analysis fails, allow the request
            originalSend.call(xhr, body);
          }
        };

        return xhr;
      } as any;

      // Store interceptor flag
      requestInterceptorRef.current = true;
    },
    [options, scanInput, showAlert]
  );

  // Set up initial DOM scanning and request interception
  useEffect(() => {
    if (options.scanDom) {
      startDomScanning(options);
    }

    if (options.scanRequests) {
      interceptRequests(true);
    }

    return () => {
      // Clean up
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }

      // Remove request interceptors
      if (requestInterceptorRef.current) {
        if (originalFetch.current) {
          window.fetch = originalFetch.current;
        }
        if (originalXHR.current) {
          window.XMLHttpRequest = originalXHR.current;
        }
      }
    };
  }, [options, startDomScanning, interceptRequests]);

  return (
    <NehonixShieldContext.Provider
      value={{
        scanUrl: analyzeUrl,
        scanInput,
        provideFeedback,
        getPerformanceMetrics,
        scanDom,
        interceptRequests,
        setShieldOptions,
        currentOptions: options,
        maliciousElements,
        blockedRequests,
        clearAlerts,
        resetStats,
      }}
    >
      {children}

      {/* Render alerts */}
      {alerts.map((alert) => (
        <SecurityAlert
          key={alert.id}
          message={alert.message}
          type={alert.type}
          details={alert.details}
          onDismiss={() =>
            setAlerts((prev) => prev.filter((a) => a.id !== alert.id))
          }
          position={options.alertPosition}
        />
      ))}
    </NehonixShieldContext.Provider>
  );
};

