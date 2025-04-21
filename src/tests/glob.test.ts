import { NehonixURIProcessor } from "..";
import NDS from "../services/NehonixDec.service";
import NES from "../services/NehonixEnc.service";
const uri = "http://localhost:8788/api/quarantine?testUri=83";

const nested_enc = `http://localhost:8788/api/quarantine?testUri=83?test2&teste/pp/?test=entr&en=fr&t=hello%20world`;
// const mockUri = `http://localhost:8788/api/quarantine?testUri=83?test2&teste/pp/?test=entr&en=fr&t=hello%20world`;

// console.log(
//   "nested_enc result: ",
//   NDS.decode({
//     input: nested_enc,
//     encodingType: "any",
//   })
// );

// const mockUri =
//   "https://nehonix.space?test=\x74\x72\x75\x65&p2=aGVsbG8gd29ybGQsIEknbSB0ZXN0aW5n&test2=65742068692062726f2075277265207573696e6720746865206c6962&ok=thank%20to%20nehonix&test5=nehonix.space&user=\112\157\150\156\40\104\157\145";

// console.log(
//   "mockUri decode result: ",
//   NDS.decode({
//     encodingType: "any",
//     input: mockUri,
//   })
// );

// // Basic URL with encoded parameters
// const result1 = NDS.decode({
//   input: "http://localhost:8788/api/quarantine?test=SGVsbG8gV29ybGQ%3D",
//   encodingType: "any",
// });
// console.log("result1: ", result1); // http://localhost:8788/api/quarantine?test=Hello World

// // Complex nested URL with multiple encodings
// const result2 = NDS.decode({
//   input: "687474703a2f2f3132372e302e302e313a353530302f696e6465782e68746d6c",
//   encodingType: "any",
// });
// console.log("result2: ", result2); // http://localhost:8788/api/quarantine?testUri=Hello World&t=hello world

// // Mixed content with various encodings
// const result3 = NDS.decode({
//   input:
//     "Check this: %3Cscript%3Ealert('XSS')%3C/script%3E and this too: SGVsbG8gV29ybGQ=",
//   encodingType: "any",
// });
// console.log("result3: ", result3); // Check this: <script>alert('XSS')</script> and this too: Hello World

// const t = NDS.decodeAnyToPlaintext(
//   "\x25\x32\x35\x33\x36\x25\x32\x35\x33\x31\x25\x32\x35\x33\x34\x25\x32\x35\x33\x37\x25\x32\x35\x33\x35\x25\x32\x35\x33\x36\x25\x32\x35\x33\x37\x25\x32\x35\x33\x33\x25\x32\x35\x33\x36\x25\x32\x35\x33\x32\x25\x32\x35\x33\x34\x25\x32\x35\x33\x37\x25\x32\x35\x33\x33\x25\x32\x35\x33\x38\x25\x32\x35\x33\x36\x25\x32\x35\x33\x37\x25\x32\x35\x33\x36\x25\x32\x35\x33\x34\x25\x32\x35\x33\x33\x25\x32\x35\x33\x32\x25\x32\x35\x33\x33\x25\x32\x35\x33\x39\x25\x32\x35\x33\x37\x25\x32\x35\x33\x39\x25\x32\x35\x33\x36\x25\x32\x35\x33\x32\x25\x32\x35\x33\x34\x25\x32\x35\x33\x37\x25\x32\x35\x33\x35\x25\x32\x35\x33\x31\x25\x32\x35\x33\x33\x25\x32\x35\x36\x34"
// );
console.log("result 4: ", NDS.decodeAnyToPlaintext("ORSXG5A="));
// console.log("result 4 value: ", t.val());
