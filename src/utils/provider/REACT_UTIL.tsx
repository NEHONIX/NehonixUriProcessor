import React, { createContext, useCallback } from "react";
import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
} from "../../services/MaliciousPatterns.service";
import { NSB } from "../../services/NehonixSecurityBooster.service";
import { ShieldContextType } from "./provider.type";

/**
 * NSB context
 */
export const NehonixShieldContext = createContext<
  ShieldContextType | undefined
>(undefined);

/**
 * NSB provider props
 */
interface NsbProviderProps {
  children: React.ReactNode;
  defaultOptions?: MaliciousPatternOptions;
}

/**
 * NSB provider component
 * @param children - React children
 * @param defaultOptions - Default NSB analysis options
 */
export const NehonixShieldProvider: React.FC<NsbProviderProps> = ({
  children,
  defaultOptions,
}) => {
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

  return (
    <NehonixShieldContext.Provider
      value={{
        scanUrl: analyzeUrl,
        provideFeedback,
        getPerformanceMetrics,
        scanInput,
      }}
    >
      {children}
    </NehonixShieldContext.Provider>
  );
};
