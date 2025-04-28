import React, { createContext, useCallback, useEffect, useState } from "react";
import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
} from "../../services/MaliciousPatterns.service";
import { NSB } from "../../services/NehonixSecurityBooster.service";
import {
  DomAnalysisOptions,
  ExtendedShieldContextType,
  NsbProviderProps,
  RequestAnalysisOptions,
} from "./provider.type";
import { useNehonixShield } from "./REACT_HOOK";

/**
 * v2.3.1
 * Extended NSB context with DOM and request analysis
 */
export const NehonixShieldContext = createContext<
  ExtendedShieldContextType | undefined
>(undefined);

/**
 * Enhanced NSB provider component
 */
export const NehonixShieldProvider: React.FC<NsbProviderProps> = ({
  children,
  defaultOptions,
  autoBlocking = true,
}) => {
  const [blockingEnabled, setBlockingEnabled] = useState(
    autoBlocking
  );
  const [lastAnalysisResult, setLastAnalysisResult] =
    useState<MaliciousPatternResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [requestObserver, setRequestObserver] = useState<any>(null);

  const analyzeUrl = useCallback(
    async (url: string, options: MaliciousPatternOptions = {}) => {
      const mergedOptions = { ...defaultOptions, ...options };
      return await NSB.analyzeUrl(url, mergedOptions);
    },
    [defaultOptions]
  );

  const scanInput = useCallback(
    async (input: string, options: MaliciousPatternOptions = {}) => {
      const mergedOptions = { ...defaultOptions, ...options };
      const url = "http://mock.nehonix.space";
      return await NSB.analyzeUrl(url + "q=" + input, mergedOptions);
    },
    [defaultOptions]
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

  // NEW METHODS

  /**
   * Analyzes the current DOM for malicious patterns
   */
  const analyzeDom = useCallback(
    async (options: DomAnalysisOptions = {}) => {
      setIsAnalyzing(true);
      try {
        const {
          targetSelector = "body",
          includeAttributes = true,
          includeScripts = true,
          includeLinks = true,
          scanIframes = false,
          ...nsbOptions
        } = options;

        const mergedOptions = { ...defaultOptions, ...nsbOptions };
        const target = document.querySelector(targetSelector) || document.body;

        // Clone the target to avoid modifying the actual DOM
        const clonedTarget = target.cloneNode(true) as HTMLElement;

        // Get the content to analyze
        let contentToAnalyze = clonedTarget.innerHTML;

        // Include scripts if requested
        if (includeScripts) {
          const scripts = Array.from(document.querySelectorAll("script"));
          const scriptContent = scripts
            .map((script) => script.innerHTML)
            .join("\n");
          contentToAnalyze += `\n${scriptContent}`;
        }

        // Include attributes if requested
        if (includeAttributes) {
          const elements = Array.from(document.querySelectorAll("*"));
          const attributeContent = elements
            .flatMap((el) => Array.from(el.attributes))
            .map((attr) => `${attr.name}="${attr.value}"`)
            .join("\n");
          contentToAnalyze += `\n${attributeContent}`;
        }

        // Include links if requested
        if (includeLinks) {
          const links = Array.from(
            document.querySelectorAll(
              "a[href], link[href], img[src], script[src], iframe[src]"
            )
          );
          const linkContent = links
            .map(
              (el) => el.getAttribute("href") || el.getAttribute("src") || ""
            )
            .filter((url) => url !== "")
            .join("\n");
          contentToAnalyze += `\n${linkContent}`;
        }

        // Include iframe content if requested
        if (scanIframes) {
          try {
            const iframes = Array.from(document.querySelectorAll("iframe"));
            for (const iframe of iframes) {
              try {
                const iframeDocument =
                  iframe.contentDocument || iframe.contentWindow?.document;
                if (iframeDocument) {
                  contentToAnalyze += `\n${iframeDocument.body.innerHTML}`;
                }
              } catch (error) {
                console.warn(
                  "Could not access iframe content due to same-origin policy:",
                  error
                );
              }
            }
          } catch (error) {
            console.warn("Error scanning iframes:", error);
          }
        }

        // Analyze the content
        const result = await NSB.analyzeUrl(
          `http://mock.nehonix.space?dom=${encodeURIComponent(
            contentToAnalyze
          )}`,
          mergedOptions
        );

        setLastAnalysisResult(result);

        // Block the display if malicious content is detected and blocking is enabled
        if (result.isMalicious && blockingEnabled) {
          // Create a blocking overlay
          const overlay = document.createElement("div");
          overlay.style.position = "fixed";
          overlay.style.top = "0";
          overlay.style.left = "0";
          overlay.style.width = "100%";
          overlay.style.height = "100%";
          overlay.style.backgroundColor = "rgba(255, 0, 0, 0.1)";
          overlay.style.zIndex = "9999";
          overlay.style.display = "flex";
          overlay.style.flexDirection = "column";
          overlay.style.alignItems = "center";
          overlay.style.justifyContent = "center";
          overlay.style.padding = "20px";
          overlay.style.boxSizing = "border-box";

          const message = document.createElement("div");
          message.style.backgroundColor = "white";
          message.style.padding = "20px";
          message.style.borderRadius = "5px";
          message.style.maxWidth = "80%";
          message.style.boxShadow = "0 0 10px rgba(0, 0, 0, 0.5)";

          message.innerHTML = `
            <h2>Nehonix Security Warning</h2>
            <p>Malicious content detected!</p>
            <p>Details: ${result.detectedPatterns
              .map(
                (p) =>
                  `<strong>${p.type}</strong>: ${p.matchedValue} (${p.location})`
              )
              .join("<br>")}</p>
            <p>Recommendation: ${result.recommendation}</p>
            <button id="nsb-continue-anyway">Continue Anyway</button>
            <button id="nsb-block-page">Block Page</button>
            powered by <a href="https://lab.nehonix.space/nehonix_viewer/_doc/NehonixUriProcessor/readme">NEHONIX</a>
          `;

          overlay.appendChild(message);
          document.body.appendChild(overlay);

          // Add event listeners to buttons
          document
            .getElementById("nsb-continue-anyway")
            ?.addEventListener("click", () => {
              document.body.removeChild(overlay);
            });

          document
            .getElementById("nsb-block-page")
            ?.addEventListener("click", () => {
              window.location.href = "about:blank";
            });
        }

        return result;
      } catch (error) {
        console.error("Error analyzing DOM:", error);
        const errorResult: MaliciousPatternResult = {
          isMalicious: false,
          detectedPatterns: [],
          score: 0,
          confidence: "low",
          recommendation: "Error analyzing DOM: " + String(error),
          contextAnalysis: {
            relatedPatterns: [],
            entropyScore: 0,
            anomalyScore: 0,
            encodingLayers: 0,
          },
        };
        setLastAnalysisResult(errorResult);
        return errorResult;
      } finally {
        setIsAnalyzing(false);
      }
    },
    [defaultOptions, blockingEnabled]
  );

  /**
   * Starts monitoring network requests for malicious patterns
   */
  const analyzeRequests = useCallback(
    (options: RequestAnalysisOptions = {}) => {
      const {
        includeXHR = true,
        includeFetch = true,
        includeImages = false,
        includeScripts = true,
        blockOnMalicious = blockingEnabled,
        ...nsbOptions
      } = options;

      const mergedOptions = { ...defaultOptions, ...nsbOptions };

      // Stop any existing observer
      stopRequestAnalysis();

      // Create a new observer instance
      const observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        for (const entry of entries) {
          // Only process resource entries
          if (entry.entryType === "resource") {
            const resourceEntry = entry as PerformanceResourceTiming;

            // Apply filters
            const isXHR = resourceEntry.initiatorType === "xmlhttprequest";
            const isFetch = resourceEntry.initiatorType === "fetch";
            const isImage = resourceEntry.initiatorType === "img";
            const isScript = resourceEntry.initiatorType === "script";

            const shouldAnalyze =
              (includeXHR && isXHR) ||
              (includeFetch && isFetch) ||
              (includeImages && isImage) ||
              (includeScripts && isScript);

            if (shouldAnalyze) {
              // Analyze the URL
              NSB.analyzeUrl(resourceEntry.name, mergedOptions)
                .then((result) => {
                  setLastAnalysisResult(result);

                  if (result.isMalicious && blockOnMalicious) {
                    console.warn(
                      "Malicious request detected:",
                      resourceEntry.name
                    );
                    console.warn("Analysis result:", result);

                    // For demonstration purposes - in a real implementation,
                    // you would need to prevent the request from completing
                    // This is challenging as PerformanceObserver only notices
                    // requests after they start loading

                    // Show a notification
                    if (
                      "Notification" in window &&
                      Notification.permission === "granted"
                    ) {
                      new Notification("Security Warning", {
                        body: `Malicious request detected: ${resourceEntry.name}`,
                        icon: "/path/to/security-icon.png",
                      });
                    }
                  }
                })
                .catch((error) => {
                  console.error("Error analyzing request:", error);
                });
            }
          }
        }
      });

      // Start observing
      observer.observe({ entryTypes: ["resource"] });

      // Store the observer for cleanup
      setRequestObserver(observer);
    },
    [defaultOptions, blockingEnabled]
  );

  /**
   * Stops monitoring network requests
   */
  const stopRequestAnalysis = useCallback(() => {
    if (requestObserver) {
      requestObserver.disconnect();
      setRequestObserver(null);
    }
  }, [requestObserver]);

  // Clean up the request observer when the component unmounts
  useEffect(() => {
    return () => {
      stopRequestAnalysis();
    };
  }, [stopRequestAnalysis]);

  return (
    <NehonixShieldContext.Provider
      value={{
        scanUrl: analyzeUrl,
        provideFeedback,
        getPerformanceMetrics,
        scanInput,
        analyzeDom,
        analyzeRequests,
        stopRequestAnalysis,
        blockingEnabled,
        setBlockingEnabled,
        lastAnalysisResult,
        isAnalyzing,
      }}
    >
      {children}
    </NehonixShieldContext.Provider>
  );
};

/**
 * HOC to automatically analyze DOM when component mounts
 */
export const withDomAnalysis = <P extends object>(
  Component: React.ComponentType<P>,
  options: DomAnalysisOptions = {}
) => {
  return (props: P) => {
    const { analyzeDom, isAnalyzing, lastAnalysisResult } = useNehonixShield();

    useEffect(() => {
      analyzeDom(options);
    }, []);

    return (
      <Component
        {...props}
        nsbIsAnalyzing={isAnalyzing}
        nsbAnalysisResult={lastAnalysisResult}
      />
    );
  };
};
