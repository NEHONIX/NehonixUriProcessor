import { useEffect } from "react";
import { RequestAnalysisOptions } from "./provider.type";
import { useNehonixShield } from "./REACT_HOOK";

/**
 * Component that provides automatic request protection
 */
export const RequestProtector: React.FC<{
  children: React.ReactNode;
  options?: RequestAnalysisOptions;
}> = ({ children, options = {} }) => {
  const { analyzeRequests, stopRequestAnalysis } = useNehonixShield();

  useEffect(() => {
    // Start analyzing requests
    analyzeRequests(options);

    // Clean up
    return () => {
      stopRequestAnalysis();
    };
  }, [analyzeRequests, stopRequestAnalysis, options]);

  return <>{children}</>;
};
