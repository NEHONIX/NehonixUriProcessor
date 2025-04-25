import { useContext } from "react";
import { ShieldContextType } from "./provider.type";
import { NehonixShieldContext } from "./REACT_UTIL";

/**
 * Custom hook for NSB security analysis
 * @returns NSB context methods
 * @throws Error if used outside NsbSecurityProvider
 */
export const useNehonixShield = (): ShieldContextType => {
  const context = useContext(NehonixShieldContext);
  if (!context) {
    throw new Error(
      "useNsbSecurity must be used within an NsbSecurityProvider."
    );
  }
  return context;
};
