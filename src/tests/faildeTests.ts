/*Manual testing failed tests */

import NDS from "../services/NehonixDec.service";

function runTest() {
  function assertEqual(received: string, expected: string, name: string) {
    console.log(
      `📍❌ NehonixLib ${name.toLocaleLowerCase()} for "${expected}" but we received "${received}" `
    );
    console.log(
      "Details: ",
      {
        received,
        expected,
        name,
      },
      "\n"
    );
  }
  {
    //1. Should decode hex string correctly (specific method)
    const rawHexInput =
      "68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374";
    const expected = "https://app.chariow.com/auth/login?test";
    assertEqual(
      NDS.decode({ input: rawHexInput, encodingType: "hex" }),
      expected,
      "Should decode hex string correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(rawHexInput).val(),
      expected,
      "Should decode hex string correctly (auto-detect)"
    );
  }
  {
    //Should decode rot13 correctly (auto-detect)
    const rot13Input = "uggcf://ncc.punevbj.pbz/nhgu/ybtva?grfg";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: rot13Input, encodingType: "rot13" }),
      expected,
      "Should decode rot13 correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(rot13Input).val(),
      expected,
      "Should decode rot13 correctly (auto-detect)"
    );
  }
  {
    //Should decode double-nested base64
    const doubleB64 =
      "YUhSMGNITTZMeTloY0hBdVkyaGhjbWx2ZHk1amIyMHZZWFYwYUM5c2IyZHBiajkwWlhOMQ==";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(doubleB64).val(),
      expected,
      "Should decode double-nested base64"
    );
  }
  {
    //Should decode hex within URL encoding
    const hexInUrl =
      "68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374%3D";
    const expected = "https://app.chariow.com/auth/login?test=";

    assertEqual(
      NDS.decodeAnyToPlaintext(hexInUrl).val(),
      expected,
      "Should decode hex within URL encoding"
    );
  }

  {
    //5 Should decode triple-nested encodings

    const tripleNested = "ZUhKMFkzTTBNQSUzRCUzRA==";
    const expected = "test";

    assertEqual(
      NDS.decodeAnyToPlaintext(tripleNested).val(),
      expected,
      "Should decode triple-nested encodings"
    );
  }

  {
    //6 Should handle urlWithComplexEnc2 correctly
    const urlWithComplexEnc2 =
      "https://app.chariow.com/stores?test=68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374&&test2=https%3A%2F%2Fapp.chariow.com%2Fauth%2Flogin%3Ftes";
    const expected =
      "https://app.chariow.com/stores?test=https://app.chariow.com/auth/login?test&&test2=https://app.chariow.com/auth/login?tes";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithComplexEnc2).val(),
      expected,
      "Should handle urlWithComplexEnc2 correctly"
    );
  }
}

runTest();
