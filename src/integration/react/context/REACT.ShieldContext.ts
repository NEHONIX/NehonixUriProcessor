import React from "react";
import { NehonixShieldContextT } from "../../types/frameworks.type";

// Create the context
export const NehonixShieldContext =
  React.createContext<NehonixShieldContextT | null>(null);
