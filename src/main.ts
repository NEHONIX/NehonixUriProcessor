import { NehonixEncService } from "./services/NehonixEnc.service";
import { SecurityRules } from "./rules/security.rules";
import { NehonixDecService } from "./services/NehonixDec.service";

/**
 * URI Encoding Detector and Decoder
 * A comprehensive library to detect and decode different types of URI encoding
 * Useful for security testing and attack analysis
 */

class NehonixURIProcessor {
  //Modules and services
  private static enc: typeof NehonixEncService = NehonixEncService;
  private static dec: typeof NehonixDecService = NehonixDecService;
  private static rules: typeof SecurityRules = SecurityRules;

  //methods
  static generateWAFBypassVariants =
    NehonixURIProcessor.rules.generateWAFBypassVariants;
  static analyzeURL = NehonixURIProcessor.rules.analyzeURL;
  static encode = NehonixURIProcessor.enc.encode;
  static detectEncoding = NehonixURIProcessor.dec.detectEncoding;
  static detectAndDecode = NehonixURIProcessor.dec.detectAndDecode;
  static decode = NehonixURIProcessor.dec.decode;
}
// export

export { NehonixURIProcessor as NURIPocess };
export default NehonixURIProcessor;
