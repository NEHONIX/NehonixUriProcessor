import { DomAnalysisOptions, RequestAnalysisOptions } from "./provider.type";
import * as nehonix from "./REACT.NehonixDomProtector";
import { RequestProtector } from "./REACT.RequestProtector";

/**
 * Component that provides comprehensive protection
 */
export const NehonixProtector: React.FC<{
  children: React.ReactNode;
  domOptions?: DomAnalysisOptions;
  requestOptions?: RequestAnalysisOptions;
  domInterval?: number | null;
}> = ({
  children,
  domOptions = {},
  requestOptions = {},
  domInterval = null,
}) => {
  return (
    <nehonix.NehonixDomProtector options={domOptions} interval={domInterval}>
      <RequestProtector options={requestOptions}>{children}</RequestProtector>
    </nehonix.NehonixDomProtector>
  );
};
