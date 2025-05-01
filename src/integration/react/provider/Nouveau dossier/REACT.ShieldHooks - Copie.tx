import React, { useContext, useEffect, useState, useCallback } from "react";
import { NehonixShieldContext } from "../context/REACT.ShieldContext";
import type {
  NehonixShieldConfig,
  NehonixShieldContextT,
  ShieldAnalysisResult,
} from "../../types/frameworks.type";

import {
  MaliciousPatternResult,
  DetectedPattern,
} from "../../../services/MaliciousPatterns.service";
import { NSB } from "../../../services/NehonixSecurityBooster.service";
import NDS from "../../../services/NehonixDec.service";

/**
 * Hook for accessing threat information
 * @returns Object with threat detection information and methods
 */
export const useThreats = () => {
  const context = useContext(NehonixShieldContext);
  if (!context) {
    throw new Error("useThreats must be used within a NehonixShieldProvider");
  }

  const { analysisResults, forceScan, clearResults } = context;

  const [activeThreats, setActiveThreats] = useState<DetectedPattern[]>([]);
  const [threatSeverity, setThreatSeverity] = useState<
    "none" | "low" | "medium" | "high"
  >("none");

  // Update active threats when analysis results change
  useEffect(() => {
    const newActiveThreats = analysisResults.activeThreats || [];
    setActiveThreats(newActiveThreats);

    // Determine highest severity
    if (newActiveThreats.length === 0) {
      setThreatSeverity("none");
    } else {
      const hasSeverity = (severity: string) =>
        newActiveThreats.some((threat) => threat.severity === severity);

      if (hasSeverity("high")) {
        setThreatSeverity("high");
      } else if (hasSeverity("medium")) {
        setThreatSeverity("medium");
      } else {
        setThreatSeverity("low");
      }
    }
  }, [analysisResults]);

  // Group threats by type
  const threatsByType = useCallback(() => {
    const grouped: Record<string, DetectedPattern[]> = {};

    activeThreats.forEach((threat) => {
      if (!grouped[threat.type]) {
        grouped[threat.type] = [];
      }
      grouped[threat.type].push(threat);
    });

    return grouped;
  }, [activeThreats]);

  // Get most recent threats (last 24 hours)
  const recentThreats = useCallback(() => {
    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    return activeThreats.filter(
      (threat) => ((threat as any)?.timestamp || 0) > oneDayAgo
    );
  }, [activeThreats]);

  return {
    activeThreats,
    threatSeverity,
    threatsByType: threatsByType(),
    recentThreats: recentThreats(),
    totalThreatsDetected: analysisResults.totalScanned,
    totalThreatsBlocked: analysisResults.totalBlocked,
    scanNow: forceScan,
    clearThreatHistory: clearResults,
  };
};

/**
 * Interface for shield monitoring data
 */
interface ShieldMonitoringData {
  isActive: boolean;
  lastScanTime: Date | null;
  nextScanTime: Date | null;
  scanCount: number;
  avgScanTime: number;
  isBackgroundScanningEnabled: boolean;
  isInterceptionEnabled: boolean;
  isDeepScanEnabled: boolean;
}

/**
 * Hook for monitoring the shield's status
 * @returns Shield monitoring information
 */
export const useShieldMonitoring = () => {
  const context = useContext(NehonixShieldContext);
  if (!context) {
    throw new Error(
      "useShieldMonitoring must be used within a NehonixShieldProvider"
    );
  }

  const { config, analysisResults, isScanning } = context;
  const [monitoringData, setMonitoringData] = useState<ShieldMonitoringData>({
    isActive: false,
    lastScanTime: null,
    nextScanTime: null,
    scanCount: 0,
    avgScanTime: 0,
    isBackgroundScanningEnabled: config.enableBackgroundScanning,
    isInterceptionEnabled: config.interceptRequests,
    isDeepScanEnabled: config.enableDeepScan,
  });

  // Update monitoring data when relevant state changes
  useEffect(() => {
    const lastScanTimestamp = analysisResults.lastScanTimestamp;
    const lastScanTime = lastScanTimestamp ? new Date(lastScanTimestamp) : null;

    // Calculate next scan time if background scanning is enabled
    let nextScanTime: Date | null = null;
    if (config.enableBackgroundScanning && lastScanTime) {
      nextScanTime = new Date(lastScanTimestamp + config.scanInterval);
    }

    setMonitoringData({
      isActive: isScanning,
      lastScanTime,
      nextScanTime,
      scanCount: analysisResults.performanceMetrics.scanCount,
      avgScanTime: analysisResults.performanceMetrics.avgScanTime,
      isBackgroundScanningEnabled: config.enableBackgroundScanning,
      isInterceptionEnabled: config.interceptRequests,
      isDeepScanEnabled: config.enableDeepScan,
    });
  }, [config, analysisResults, isScanning]);

  return monitoringData;
};

/**
 * Hook for working with shield configuration
 * @returns Configuration objects and update methods
 */
export const useShieldConfig = () => {
  const context = useContext(NehonixShieldContext);
  if (!context) {
    throw new Error(
      "useShieldConfig must be used within a NehonixShieldProvider"
    );
  }

  const { config, updateConfig, pauseScanning, resumeScanning } = context;

  // Helper functions for common configuration changes
  const toggleBackgroundScanning = useCallback(() => {
    updateConfig({
      enableBackgroundScanning: !config.enableBackgroundScanning,
    });
  }, [config.enableBackgroundScanning, updateConfig]);

  const toggleRequestInterception = useCallback(() => {
    updateConfig({ interceptRequests: !config.interceptRequests });
  }, [config.interceptRequests, updateConfig]);

  const toggleDeepScan = useCallback(() => {
    updateConfig({ enableDeepScan: !config.enableDeepScan });
  }, [config.enableDeepScan, updateConfig]);

  const setScanInterval = useCallback(
    (intervalMs: number) => {
      updateConfig({ scanInterval: intervalMs });
    },
    [updateConfig]
  );

  const addTrustedDomain = useCallback(
    (domain: string) => {
      const trustedDomains = [...(config.urlUtils.trustedDomains || [])];
      if (!trustedDomains.includes(domain)) {
        trustedDomains.push(domain);
        updateConfig({ urlUtils: { trustedDomains } });
      }
    },
    [config.urlUtils.trustedDomains, updateConfig]
  );

  const removeTrustedDomain = useCallback(
    (domain: string) => {
      const trustedDomains = (config.urlUtils.trustedDomains || []).filter(
        (d) => d !== domain
      );
      updateConfig({ urlUtils: { trustedDomains } });
    },
    [config.urlUtils.trustedDomains, updateConfig]
  );

  const addBlacklistedPattern = useCallback(
    (pattern: string) => {
      const blacklistedPatterns = [...(config.blacklistedPatterns || [])];
      if (!blacklistedPatterns.includes(pattern)) {
        blacklistedPatterns.push(pattern);
        updateConfig({ blacklistedPatterns });
      }
    },
    [config.blacklistedPatterns, updateConfig]
  );

  const removeBlacklistedPattern = useCallback(
    (pattern: string) => {
      const blacklistedPatterns = (config.blacklistedPatterns || []).filter(
        (p) => p !== pattern
      );
      updateConfig({ blacklistedPatterns });
    },
    [config.blacklistedPatterns, updateConfig]
  );

  return {
    config,
    updateConfig,
    toggleBackgroundScanning,
    toggleRequestInterception,
    toggleDeepScan,
    setScanInterval,
    pauseScanning,
    resumeScanning,
    addTrustedDomain,
    removeTrustedDomain,
    addBlacklistedPattern,
    removeBlacklistedPattern,
  };
};

/**
 * Hook for creating a protected fetch that uses Nehonix Shield
 * @returns A secure fetch function that analyzes URLs before fetching
 */
export const useSecureFetch = () => {
  const context = useContext(NehonixShieldContext);
  if (!context) {
    throw new Error(
      "useSecureFetch must be used within a NehonixShieldProvider"
    );
  }

  const { config } = context;

  const secureFetch = useCallback(
    async (
      url: string | URL | Request,
      options?: RequestInit,
      securityOptions?: {
        bypassScan?: boolean;
        customScanOptions?: Record<string, any>;
        onBlock?: (result: MaliciousPatternResult) => void;
      }
    ) => {
      // Skip scanning if bypass is requested
      if (securityOptions?.bypassScan) {
        return fetch(url, options);
      }

      const urlString = url instanceof Request ? url.url : url.toString();

      try {
        // Check if URL is in trusted domains
        if (
          config.urlUtils.trustedDomains?.some((domain) =>
            urlString.includes(domain)
          )
        ) {
          return fetch(url, options);
        }

        // Analyze URL before fetching
        const scanOptions = {
          ...config.scanOptions,
          ...(securityOptions?.customScanOptions || {}),
        };

        const analysisResult = await NSB.analyzeUrl(
          urlString,
          scanOptions.analyseOptions
        );

        // Block if malicious
        if (analysisResult.isMalicious && config.blockMaliciousRequests) {
          console.warn(
            "Nehonix Shield blocked malicious fetch:",
            urlString,
            analysisResult
          );

          // Call onBlock callback if provided
          if (securityOptions?.onBlock) {
            securityOptions.onBlock(analysisResult);
          } else if (config.onBlock) {
            const request =
              url instanceof Request ? url : new Request(urlString, options);
            config.onBlock(analysisResult, request);
          }

          throw new Error(
            "Request blocked by Nehonix Shield: Malicious URL detected"
          );
        }

        // Make the request if no issues found
        return fetch(url, options);
      } catch (error) {
        console.error("Error in secure fetch:", error);
        throw error;
      }
    },
    [config]
  );

  return secureFetch;
};

//main
/**
 * Hook to use the Nehonix Shield Context
 */
export const useNehonixShield = () => {
  const context = useContext(NehonixShieldContext);
  if (!context) {
    throw new Error(
      "useNehonixShield must be used within a NehonixShieldProvider"
    );
  }
  return context;
};
