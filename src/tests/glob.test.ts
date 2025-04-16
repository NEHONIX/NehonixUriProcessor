import { NehonixURIProcessor } from "..";
const uri = "http://localhost:8788/api/quarantine?testUri=83";

console.log(
  NehonixURIProcessor.checkUrl(uri, {
    strictMode: false,
  })
);
