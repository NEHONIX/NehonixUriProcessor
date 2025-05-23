import React, { useEffect, useState, useRef, createContext } from "react";
import { MaliciousPatternResult } from "../../../services/MaliciousPatterns.service";
import { NSB } from "../../../services/NehonixSecurityBooster.service";
import {
  NehonixShieldConfig,
  NehonixShieldContextT,
  ShieldAnalysisResult,
} from "../../types/frameworks.type";
import { NehonixShieldContext } from "../context/REACT.ShieldContext";
import { ncu } from "../../../utils/NehonixCoreUtils";
import NDS from "../../../services/NehonixDec.service";
import { mapConfidenceToNumber } from "./utils/confidence";

// Default configuration
const defaultConfig: NehonixShieldConfig = {
  enableBackgroundScanning: true,
  scanInterval: 30000, // 30 seconds
  interceptRequests: true,
  enableDeepScan: false,
  confidenceThreshold: 0.7, // Added for confidence-based filtering
  enableContextAnalysis: true, // Added for context-aware scanning
  scanOptions: {
    analyseOptions: {
      debug: true,
    },
    global: {
      ignoreCase: true,
      checkEncoding: true,
      maxEncodingLayers: 3,
      analyzeContext: true,
      confidence: "medium",
    },
  },
  blockMaliciousRequests: true,
  blockMaliciousResponses: true,
  urlUtils: {
    trustedDomains: [],
    dynamicWhitelist: [], // Added for runtime whitelisting
  },
  blacklistedPatterns: [],
};

// Initialize empty analysis results
const initialAnalysisResults: ShieldAnalysisResult = {
  analysisResults: [],
  lastScanTimestamp: 0,
  totalScanned: 0,
  totalBlocked: 0,
  activeThreats: [],
  performanceMetrics: {
    avgScanTime: 0,
    totalScanTime: 0,
    scanCount: 0,
  },
};

/**
 * Nehonix Shield Provider Component
 */
export const NehonixShieldProvider: React.FC<{
  children: React.ReactNode;
  initialConfig?: Partial<NehonixShieldConfig>;
}> = ({ children, initialConfig = {} }) => {
  // Merge the default config with the provided initialConfig
  const [config, setConfig] = useState<NehonixShieldConfig>({
    ...defaultConfig,
    ...initialConfig,
  });

  const [analysisResults, setAnalysisResults] = useState<ShieldAnalysisResult>(
    initialAnalysisResults
  );
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isPaused, setIsPaused] = useState<boolean>(false);

  // Use refs for values that need to be accessed in effects
  const configRef = useRef(config);
  const scanIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const urlCache = useRef<
    Map<string, { result: MaliciousPatternResult; timestamp: number }>
  >(new Map());

  // Update the config ref when config changes
  useEffect(() => {
    configRef.current = config;
  }, [config]);

  /**
   * Update the configuration
   */
  const updateConfig = (newConfig: Partial<NehonixShieldConfig>) => {
    setConfig((prevConfig) => {
      const updatedConfig = {
        ...prevConfig,
        ...newConfig,
        scanOptions: {
          ...prevConfig.scanOptions,
          ...(newConfig.scanOptions || {}),
        },
        urlUtils: {
          ...prevConfig.urlUtils,
          ...(newConfig.urlUtils || {}),
        },
      };
      return updatedConfig;
    });
  };

  /**
   * Add URL to dynamic whitelist
   */
  const addToDynamicWhitelist = (url: string) => {
    setConfig((prev) => ({
      ...prev,
      urlUtils: {
        ...prev.urlUtils,
        dynamicWhitelist: [...(prev.urlUtils.dynamicWhitelist || []), url],
      },
    }));
  };

  /**
   * Pause background scanning
   */
  const pauseScanning = () => {
    setIsPaused(true);
    if (scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }
  };

  /**
   * Resume background scanning
   */
  const resumeScanning = () => {
    if (configRef.current.enableBackgroundScanning) {
      setIsPaused(false);
      startBackgroundScanning();
    }
  };

  /**
   * Clear analysis results
   */
  const clearResults = () => {
    setAnalysisResults(initialAnalysisResults);
    urlCache.current.clear();
  };

  /**
   * Start background scanning
   */
  const startBackgroundScanning = () => {
    if (scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
    }

    scanIntervalRef.current = setInterval(() => {
      if (!isPaused && configRef.current.enableBackgroundScanning) {
        performScan();
      }
    }, configRef.current.scanInterval);
  };

  /**
   * Perform a security scan
   */
  const performScan = async () => {
    setIsScanning(true);
    const startTime = performance.now();

    try {
      const currentUrl = NDS.decodeAnyToPlaintext(window.location.href).val();

      // Check cache first
      const cached = urlCache.current.get(currentUrl);
      if (cached && Date.now() - cached.timestamp < 60 * 1000) {
        return cached.result;
      }

      // Context analysis
      const context = configRef.current.enableContextAnalysis
        ? {
            referrer: document.referrer,
            userAgent: navigator.userAgent,
            pageTitle: document.title,
          }
        : {};

      const urlResult = await NSB.analyzeUrl(currentUrl, {
        ...configRef.current.scanOptions.analyseOptions,
        /**
         * TODO:  context,
         * we'll add context later
         * */
      });

      // Apply confidence threshold
      if (
        urlResult.isMalicious &&
        mapConfidenceToNumber(urlResult.confidence) <
          configRef.current.confidenceThreshold
      ) {
        urlResult.isMalicious = false;
        console.warn("Low-confidence threat detected:", urlResult);
      }

      // Update cache
      urlCache.current.set(currentUrl, {
        result: urlResult,
        timestamp: Date.now(),
      });

      // Deep scan if enabled
      let deepScanResults: MaliciousPatternResult[] = [];
      if (configRef.current.enableDeepScan) {
        deepScanResults = await performDeepScan();
      }

      // Apply confidence threshold to deep scan results
      deepScanResults = deepScanResults.map((result) => {
        if (
          result.isMalicious &&
          mapConfidenceToNumber(result.confidence) <
            configRef.current.confidenceThreshold
        ) {
          return { ...result, isMalicious: false };
        }
        return result;
      });

      // Combine results
      const allResults = [urlResult, ...deepScanResults];
      const newActiveThreats = allResults.flatMap((result) =>
        result.detectedPatterns.filter(
          (threat) =>
            threat.severity === "high" &&
            mapConfidenceToNumber(result.confidence) >=
              configRef.current.confidenceThreshold
        )
      );

      // Update scan metrics
      const endTime = performance.now();
      const scanTime = endTime - startTime;

      setAnalysisResults((prev) => {
        const totalScanTime = prev.performanceMetrics.totalScanTime + scanTime;
        const scanCount = prev.performanceMetrics.scanCount + 1;

        return {
          analysisResults: [...prev.analysisResults, ...allResults],
          lastScanTimestamp: Date.now(),
          totalScanned: prev.totalScanned + allResults.length,
          totalBlocked:
            prev.totalBlocked +
            (allResults.some(
              (r) => r.isMalicious && configRef.current.blockMaliciousRequests
            )
              ? 1
              : 0),
          activeThreats: newActiveThreats,
          performanceMetrics: {
            avgScanTime: totalScanTime / scanCount,
            totalScanTime,
            scanCount,
          },
        };
      });

      // Call onDetection callback if threats were found
      if (
        allResults.some((r) => r.isMalicious) &&
        configRef.current.onDetection
      ) {
        configRef.current.onDetection(urlResult);
      }
    } catch (error) {
      console.error("Nehonix Shield scan error:", error);
    } finally {
      setIsScanning(false);
    }
  };

  /**
   * Perform a deep scan of the document and resources
   */
  const performDeepScan = async (): Promise<MaliciousPatternResult[]> => {
    const results: MaliciousPatternResult[] = [];

    try {
      // Scan all links in the document
      const links = Array.from(document.querySelectorAll("a")).map(
        (a) => a.href
      );
      const current = configRef.current;
      const opt: typeof current.urlUtils = { allowLocalhost: true };
      const checkOpt = Object.assign(current.urlUtils, opt);
      const uniqueLinks = [...new Set(links)].filter((link) => {
        const checkLink = ncu.checkUrl(link, checkOpt);

        // Filter out links that don't have a valid protocol or are in trusted/dynamic whitelists
        if (!checkLink.isValid) return false;

        if (
          current.urlUtils.trustedDomains?.some((domain) =>
            link.includes(domain)
          ) ||
          current.urlUtils.dynamicWhitelist?.includes(link)
        ) {
          return false;
        }

        return true;
      });

      // Limit the number of links to scan
      const linksToScan = uniqueLinks.slice(0, 10);

      // Scan each link
      for (const link of linksToScan) {
        try {
          const norm = await NDS.asyncDecodeAnyToPlainText(link);
          const url = norm.val();
          const result = await NSB.analyzeUrl(
            url.normalize("NFC"),
            current.scanOptions.analyseOptions
          );
          if (
            result.isMalicious &&
            mapConfidenceToNumber(result.confidence) <
              current.confidenceThreshold
          ) {
            result.isMalicious = false;
          }
          results.push(result);
        } catch (error) {
          console.error(`Error scanning link ${link}:`, error);
        }
      }

      // Scan script sources
      const scripts = Array.from(document.querySelectorAll("script"))
        .map((s) => s.src)
        .filter(Boolean);
      const uniqueScripts = [...new Set(scripts)].filter(
        (src) =>
          ncu.checkUrl(src, checkOpt).isValid &&
          !current.urlUtils.trustedDomains?.some((domain) =>
            src.includes(domain)
          ) &&
          !current.urlUtils.dynamicWhitelist?.includes(src)
      );

      for (const src of uniqueScripts.slice(0, 5)) {
        try {
          const norm = await NDS.asyncDecodeAnyToPlainText(src);
          const url = norm.val();
          const result = await NSB.analyzeUrl(
            url.normalize("NFC"),
            current.scanOptions.analyseOptions
          );
          if (
            result.isMalicious &&
            mapConfidenceToNumber(result.confidence) <
              current.confidenceThreshold
          ) {
            result.isMalicious = false;
          }
          results.push(result);
        } catch (error) {
          console.error(`Error scanning script ${src}:`, error);
        }
      }

      // Scan iframes
      const iframes = Array.from(document.querySelectorAll("iframe"))
        .map((i) => i.src)
        .filter(Boolean);
      const uniqueIframes = [...new Set(iframes)].filter(
        (src) =>
          ncu.checkUrl(src, checkOpt).isValid &&
          !current.urlUtils.trustedDomains?.some((domain) =>
            src.includes(domain)
          ) &&
          !current.urlUtils.dynamicWhitelist?.includes(src)
      );

      for (const src of uniqueIframes) {
        try {
          const norm = await NDS.asyncDecodeAnyToPlainText(src);
          const url = norm.val();
          const result = await NSB.analyzeUrl(
            url.normalize("NFC"),
            current.scanOptions.analyseOptions
          );
          if (
            result.isMalicious &&
            mapConfidenceToNumber(result.confidence) <
              current.confidenceThreshold
          ) {
            result.isMalicious = false;
          }
          results.push(result);
        } catch (error) {
          console.error(`Error scanning iframe ${src}:`, error);
        }
      }
    } catch (error) {
      console.error("Deep scan error:", error);
    }

    return results;
  };

  /**
   * Force an immediate scan
   */
  const forceScan = async () => {
    await performScan();
  };

  // Initialize request interception
  useEffect(() => {
    if (config.interceptRequests) {
      setupRequestInterception();
    }

    return () => {
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
      }
    };
  }, [config.interceptRequests]);

  // Start background scanning when enabled
  useEffect(() => {
    if (config.enableBackgroundScanning && !isPaused) {
      startBackgroundScanning();
      performScan();
    } else if (!config.enableBackgroundScanning && scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }

    return () => {
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
      }
    };
  }, [config.enableBackgroundScanning, config.scanInterval, isPaused]);

  /**
   * Setup request interception using fetch API
   */
  const setupRequestInterception = () => {
    const originalFetch = window.fetch;

    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : (input as any)?.url ?? "";

      if (
        configRef.current.urlUtils.trustedDomains?.some((domain) =>
          url.includes(domain)
        ) ||
        configRef.current.urlUtils.dynamicWhitelist?.includes(url)
      ) {
        return originalFetch(input, init);
      }

      try {
        const norm = await NDS.asyncDecodeAnyToPlainText(url);
        const link = norm.val();
        const analysisResult = await NSB.analyzeUrl(
          link.normalize("NFC"),
          configRef.current.scanOptions.analyseOptions
        );

        if (
          analysisResult.isMalicious &&
          mapConfidenceToNumber(analysisResult.confidence) >=
            configRef.current.confidenceThreshold &&
          configRef.current.blockMaliciousRequests
        ) {
          console.warn(
            "Nehonix Shield blocked malicious request:",
            url,
            analysisResult
          );

          if (configRef.current.onBlock) {
            configRef.current.onBlock(analysisResult, new Request(url, init));
          }

          return Promise.reject(
            new Error(
              "Request blocked by Nehonix Shield: Malicious URL detected"
            )
          );
        }

        const response = await originalFetch(input, init);
        const responseClone = response.clone();

        if (configRef.current.blockMaliciousResponses) {
          try {
            const responseText = await responseClone.text();
            const contentType = response.headers.get("content-type") || "";
            if (
              contentType.includes("text/") ||
              contentType.includes("application/json")
            ) {
              const mockUrl = `http://mock.nehonix.space?data=${encodeURIComponent(
                responseText.substring(0, 2000)
              )}`;
              const norm = await NDS.asyncDecodeAnyToPlainText(mockUrl);
              const mockUrlDecoded = norm.val();
              const mockUrlNormalized = mockUrlDecoded.normalize("NFC");
              const responseAnalysis = await NSB.analyzeUrl(
                mockUrlNormalized,
                configRef.current.scanOptions.analyseOptions
              );

              if (
                responseAnalysis.isMalicious &&
                mapConfidenceToNumber(responseAnalysis.confidence) >=
                  configRef.current.confidenceThreshold
              ) {
                console.warn(
                  "Nehonix Shield blocked malicious response:",
                  url,
                  responseAnalysis
                );

                if (configRef.current.onBlock) {
                  configRef.current.onBlock(
                    responseAnalysis,
                    new Request(url, init)
                  );
                }

                return Promise.reject(
                  new Error(
                    "Response blocked by Nehonix Shield: Malicious content detected"
                  )
                );
              }
            }

            return new Response(responseText, {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers,
            });
          } catch (error) {
            console.error("Error analyzing response:", error);
            return response;
          }
        }

        return response;
      } catch (error) {
        console.error("Error in request interception:", error);
        return originalFetch(input, init);
      }
    };

    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (
      method: string,
      url: string | URL,
      ...args: any[]
    ) {
      const urlString = url.toString();
      (this as any)._nehonixUrl = urlString;
      return originalXHROpen.apply(this, [method, url, ...args] as any);
    };

    XMLHttpRequest.prototype.send = async function (
      body?: Document | XMLHttpRequestBodyInit
    ) {
      if (
        !(this as any)._nehonixUrl ||
        configRef.current.urlUtils.trustedDomains?.some((domain) =>
          (this as any)._nehonixUrl.includes(domain)
        ) ||
        configRef.current.urlUtils.dynamicWhitelist?.includes(
          (this as any)._nehonixUrl
        )
      ) {
        return originalXHRSend.apply(this, [body]);
      }

      try {
        const norm = await NDS.asyncDecodeAnyToPlainText(
          (this as any)._nehonixUrl
        );
        const link = norm.val();
        const normalisedLink = link.normalize("NFC");
        const analysisResult = await NSB.analyzeUrl(
          normalisedLink,
          configRef.current.scanOptions.analyseOptions
        );

        if (
          analysisResult.isMalicious &&
          mapConfidenceToNumber(analysisResult.confidence) >=
            configRef.current.confidenceThreshold &&
          configRef.current.blockMaliciousRequests
        ) {
          console.warn(
            "Nehonix Shield blocked malicious XHR request:",
            (this as any)._nehonixUrl,
            analysisResult
          );

          if (configRef.current.onBlock) {
            const request = new Request((this as any)._nehonixUrl);
            configRef.current.onBlock(analysisResult, request);
          }

          this.abort();

          const errorEvent = new ErrorEvent("error", {
            error: new Error(
              "Request blocked by Nehonix Shield: Malicious URL detected"
            ),
            message:
              "Request blocked by Nehonix Shield: Malicious URL detected",
          });
          this.dispatchEvent(errorEvent);

          return;
        }
      } catch (error) {
        console.error("Error in XHR interception:", error);
      }

      return originalXHRSend.apply(this, [body]);
    };
  };

  const contextValue: NehonixShieldContextT = {
    config,
    updateConfig,
    analysisResults,
    isScanning,
    pauseScanning,
    resumeScanning,
    forceScan,
    clearResults,
    addToDynamicWhitelist,
  };

  return (
    <NehonixShieldContext.Provider value={contextValue}>
      {children}
    </NehonixShieldContext.Provider>
  );
};
