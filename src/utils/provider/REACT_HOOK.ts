import { useContext } from "react";
import { ExtendedShieldContextType, ShieldContextType } from "./provider.type";
import { NehonixShieldContext } from "./REACT_UTIL";

/**
 * Custom hook for NSB security analysis
 * @returns NSB context methods
 * @throws Error if used outside NsbSecurityProvider
 */
export const useNehonixShield = (): ExtendedShieldContextType => {
  const context = useContext(NehonixShieldContext);
  if (!context) {
    throw new Error(
      "useNsbSecurity must be used within an NsbSecurityProvider."
    );
  }
  return context;
};

// /**
//  * Custom hook to use the Nehonix Shield context
//  */
// export const useNehonixShield = () => {
//   const context = React.useContext(NehonixShieldContext);
//   if (context === undefined) {
//     throw new Error(
//       "useNehonixShield must be used within a NehonixShieldProvider"
//     );
//   }
//   return context;
// };
