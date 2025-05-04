import { ENC_TYPE } from ".";

export type EncodingResult = {
  original: string;
  encoded: string;
  type: ENC_TYPE;
};

export type NestedEncodingOptions = {
  /**
   * If true, use each encoding's output as input for the next encoding
   */
  sequential?: boolean;
  /**
   * If true, include all intermediate results in the response
   */
  includeIntermediate?: boolean;
};

export type NestedEncodingResponse = {
  input: string;
  results: EncodingResult[];
  finalResult?: string; // Only relevant for sequential encoding
};
