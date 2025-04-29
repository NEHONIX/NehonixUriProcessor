import React, { useEffect } from "react";
import { DomAnalysisOptions } from "./provider.type";
import { useNehonixShield } from "./REACT_HOOK";

/**
 * Component that provides automatic DOM protection
 */
export const NehonixDomProtector: React.FC<{
  children: React.ReactNode;
  options?: DomAnalysisOptions;
  interval?: number | null;
}> = ({ children, options = {}, interval = null }) => {
  const { scanDom: analyzeDom } = useNehonixShield();

  useEffect(() => {
    // Initial analysis
    analyzeDom(options);

    // Set up interval if requested
    let intervalId: number | null = null;
    if (interval && interval > 0) {
      intervalId = window.setInterval(() => {
        analyzeDom(options);
      }, interval);
    }

    // Set up mutation observer for real-time protection
    const observer = new MutationObserver((mutations) => {
      // Only analyze if significant changes occurred
      const significantChanges = mutations.some(
        (mutation) =>
          mutation.type === "childList" &&
          (mutation.addedNodes.length > 0 || mutation.removedNodes.length > 0)
      );

      if (significantChanges) {
        analyzeDom(options);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: options.includeAttributes || false,
    });

    // Cleanup
    return () => {
      if (intervalId !== null) {
        clearInterval(intervalId);
      }
      observer.disconnect();
    };
  }, [analyzeDom, options, interval]);

  return <>{children}</>;
};