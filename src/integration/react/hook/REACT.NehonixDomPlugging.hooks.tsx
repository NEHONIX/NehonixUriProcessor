import React, { useContext, useCallback, useMemo } from "react";
import { NehonixShieldContext } from "../context/REACT.ShieldContext";
import {
  NehonixDomProcessorContext,
  NehonixDomProcessorProvider,
} from "../provider/REACT.NehonixDomProcessor";
import {
  NehonixShieldContextT,
  DomProcessorContextT,
  SecuritySuiteContext,
  NehonixShieldConfig,
  DomProcessorConfig,
  ShieldAnalysisResult,
  DomProcessorStats,
} from "../../types/frameworks.type";
import { NehonixShieldProvider } from "../provider/REACT.NehonixShield";

/**
 * Combined hook for accessing Nehonix security features
 * This hook provides a unified interface to both NehonixShield and NehonixDomProcessor
 *
 * @returns Combined security context with methods and properties from both systems
 */
export const useNehonixShieldPlugging = (): SecuritySuiteContext => {
  const shield = useContext(NehonixShieldContext);
  const domProcessor = useContext(NehonixDomProcessorContext);

  // Check if contexts are available
  if (!shield) {
    throw new Error(
      "useNehonixShieldPlugging must be used within a NehonixShieldProvider"
    );
  }

  if (!domProcessor) {
    throw new Error(
      "useNehonixShieldPlugging must be used within a NehonixDomProcessorProvider"
    );
  }

  /**
   * Force scan in both systems
   */
  const forceFullScan = useCallback(() => {
    shield.forceScan();
    domProcessor.scanDOM();
  }, [shield, domProcessor]);

  /**
   * Reset all stats and results
   */
  const resetAllStats = useCallback(() => {
    shield.clearResults();
    domProcessor.resetStats();
  }, [shield, domProcessor]);

  /**
   * Combined configuration updater
   */
  const updateConfig = useCallback(
    (
      shieldConfig?: Partial<NehonixShieldConfig>,
      domConfig?: Partial<DomProcessorConfig>
    ) => {
      if (shieldConfig) {
        shield.updateConfig(shieldConfig);
      }
      if (domConfig) {
        domProcessor.updateConfig(domConfig);
      }
    },
    [shield, domProcessor]
  );

  /**
   * Get comprehensive security report combining both systems
   */
  const getComprehensiveReport = useCallback(() => {
    const currentTimestamp = Date.now();

    return {
      shield: {
        config: shield.config,
        results: shield.analysisResults,
      },
      domProcessor: domProcessor.getSecurityReport(),
      timestamp: currentTimestamp,
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
        overallStatus:
          shield.analysisResults.totalBlocked +
            domProcessor.stats.threatsDetected >
          0
            ? "threats-detected"
            : "secure",
        scanCoverage: {
          domElementsScanned: domProcessor.stats.elementsScanned,
          urlsScanned: shield.analysisResults.totalScanned,
        },
      },
    };
  }, [shield, domProcessor]);

  /**
   * Get simple security status
   */
  const getSecurityStatus = useCallback(() => {
    return {
      isSecure:
        shield.analysisResults.totalBlocked +
          domProcessor.stats.threatsDetected ===
        0,
      activeThreats: [
        ...shield.analysisResults.activeThreats,
        ...domProcessor.stats.blockedElements.map((el) => ({
          type: el.threatTypes[0],
          severity: "high",
          timestamp: el.timestamp,
          source: `DOM element (${el.elementType})`,
          metadata: el.metadata, // Include metadata
        })),
      ],
      lastScanTime: Math.max(
        shield.analysisResults.lastScanTimestamp,
        domProcessor.stats.lastScanTimestamp
      ),
      scanning: shield.isScanning || domProcessor.stats.scanningActive,
    };
  }, [shield, domProcessor]);

  /**
   * Pause all scanning activities
   */
  const pauseAllScanning = useCallback(() => {
    shield.pauseScanning();
    domProcessor.stopScanning();
  }, [shield, domProcessor]);

  /**
   * Resume all scanning activities
   */
  const resumeAllScanning = useCallback(() => {
    shield.resumeScanning();
    if (domProcessor.config.enabled) {
      domProcessor.scanDOM();
    }
  }, [shield, domProcessor]);

  /**
   * Combined stats object
   */
  const combinedStats = useMemo(() => {
    const shieldStats: ShieldAnalysisResult = shield.analysisResults;
    const domStats: DomProcessorStats = domProcessor.stats;

    return {
      elementsScanned: domStats.elementsScanned,
      urlsScanned: shieldStats.totalScanned,
      threatsDetected: shieldStats.totalBlocked + domStats.threatsDetected,
      lastScanTimestamp: Math.max(
        shieldStats.lastScanTimestamp,
        domStats.lastScanTimestamp
      ),
      scanDuration: domStats.scanDuration,
      scanningActive: shield.isScanning || domStats.scanningActive,
      elementTypeStats: domStats.elementTypeStats,
      threatsByType: {
        ...domStats.threatsByType,
        // Could merge with shield threat types if available
      },
      blockedElements: [
        ...domStats.blockedElements,
        // Could add shield blocked URLs in a compatible format
      ],
      performance: {
        avgElementScanTime: domStats.avgProcessingTimePerElement,
        avgUrlScanTime: shieldStats.performanceMetrics.avgScanTime,
      },
    };
  }, [shield.analysisResults, domProcessor.stats]);

  // Return the combined interface
  return {
    // Original contexts for direct access if needed
    shield,
    domProcessor,

    // Combined methods
    forceFullScan,
    resetAllStats,
    getComprehensiveReport,
    getSecurityStatus,
    updateConfig,
    pauseAllScanning,
    resumeAllScanning,

    // Combined properties
    stats: combinedStats,
    isScanning: shield.isScanning || domProcessor.stats.scanningActive,
  };
};

/**
 * Combined provider component for Nehonix security plugging
 * This is a convenience wrapper that sets up both security contexts
 */
export const NehonixShieldProviderPlugging: React.FC<{
  children: React.ReactNode;
  shieldConfig?: Partial<NehonixShieldConfig>;
  domProcessorConfig?: Partial<DomProcessorConfig>;
}> = ({ children, shieldConfig = {}, domProcessorConfig = {} }) => {
  return (
    <NehonixShieldProvider initialConfig={shieldConfig}>
      <NehonixDomProcessorProvider initialConfig={domProcessorConfig}>
        {children}
      </NehonixDomProcessorProvider>
    </NehonixShieldProvider>
  );
};

/**
 * Higher-order component that injects the Nehonix security context
 *
 * @param Component The component to wrap
 * @returns A new component with the security context injected as a prop
 */
export const withNehonixShieldPlugging = <P extends object>(
  Component: React.ComponentType<P & { security: SecuritySuiteContext }>
): React.FC<P> => {
  return (props: P) => {
    const security = useNehonixShieldPlugging();
    return <Component {...props} security={security} />;
  };
};

/**
 * Security badge component - shows current security status
 */
export const NehonixShieldPluggingBadge: React.FC<{
  variant?: "minimal" | "standard" | "detailed";
  className?: string;
  style?: React.CSSProperties;
}> = ({ variant = "standard", className = "", style = {} }) => {
  const security = useNehonixShieldPlugging();
  const securityStatus = security.getSecurityStatus();

  const getStatusColor = () => {
    if (securityStatus.scanning) return "#FFA500"; // Orange for scanning
    return securityStatus.isSecure ? "#4CAF50" : "#FF0000"; // Green for secure, red for threats
  };

  const getBadgeContent = () => {
    switch (variant) {
      case "minimal":
        return (
          <div style={{ display: "flex", alignItems: "center" }}>
            <div
              style={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                backgroundColor: getStatusColor(),
                marginRight: 5,
              }}
            />
            {securityStatus.isSecure ? "Secure" : "Alert"}
          </div>
        );

      case "detailed":
        return (
          <div>
            <div style={{ display: "flex", alignItems: "center" }}>
              <div
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: "50%",
                  backgroundColor: getStatusColor(),
                  marginRight: 5,
                }}
              />
              <strong>
                {securityStatus.isSecure ? "Secure" : "Threats Detected"}
              </strong>
            </div>
            <div style={{ fontSize: "0.8em", marginTop: 5 }}>
              <div>Elements scanned: {security.stats.elementsScanned}</div>
              <div>URLs scanned: {security.stats.urlsScanned}</div>
              {securityStatus.activeThreats.length > 0 && (
                <div>
                  Active threats: {securityStatus.activeThreats.length}
                  <ul style={{ margin: "5px 0", paddingLeft: 20 }}>
                    {securityStatus.activeThreats.map((threat, index) => (
                      <li key={index}>
                        <strong>Type:</strong> {threat.type || "Unknown"}
                        <br />
                        <strong>Source:</strong> {threat.source || "N/A"}
                        <br />
                        {threat.metadata && (
                          <>
                            <strong>DOM Location:</strong>{" "}
                            {threat.metadata.domLocation.substring(0, 100) +
                              (threat.metadata.domLocation.length > 100
                                ? "..."
                                : "")}
                            <br />
                            {threat.metadata.elementId && (
                              <>
                                <strong>ID:</strong> {threat.metadata.elementId}
                                <br />
                              </>
                            )}
                            {threat.metadata.className && (
                              <>
                                <strong>Class:</strong>{" "}
                                {threat.metadata.className}
                                <br />
                              </>
                            )}
                            {threat.metadata.parentElement && (
                              <>
                                <strong>Parent:</strong>{" "}
                                {threat.metadata.parentElement.tagName}
                                {threat.metadata.parentElement.id
                                  ? ` (#${threat.metadata.parentElement.id})`
                                  : ""}
                                <br />
                              </>
                            )}
                            <strong>DOM Path:</strong> {threat.metadata.domPath}
                            <br />
                            {threat.metadata.innerTextSnippet && (
                              <>
                                <strong>Inner Text:</strong>{" "}
                                {threat.metadata.innerTextSnippet}
                                <br />
                              </>
                            )}
                          </>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <button
              onClick={security.forceFullScan}
              style={{
                marginTop: 5,
                padding: "2px 5px",
                fontSize: "0.8em",
              }}
            >
              Scan Now
            </button>
          </div>
        );

      default: // standard
        return (
          <div style={{ display: "flex", alignItems: "center" }}>
            <div
              style={{
                width: 10,
                height: 10,
                borderRadius: "50%",
                backgroundColor: getStatusColor(),
                marginRight: 5,
              }}
            />
            <div>
              <div>
                {securityStatus.isSecure
                  ? "Secure"
                  : `Threats: ${securityStatus.activeThreats.length}`}
              </div>
              <div style={{ fontSize: "0.8em" }}>
                {securityStatus.scanning ? "Scanning..." : "Idle"}
              </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div
      className={`nehonix-security-badge ${className}`}
      style={{
        padding: 10,
        border: `1px solid ${getStatusColor()}`,
        borderRadius: 4,
        ...style,
      }}
    >
      {getBadgeContent()}
    </div>
  );
};
