async function runTest() {
  try {
    const res = await fetch("localhost:3000/api/secure", {
      method: "POST",
      body: JSON.stringify({
        id: 1,
        jsonrpc: "2.0",
        method: "eth_blockNumber",
      }),
    });
    console.log("res: ", res);
  } catch (error) {
    console.error("erreur: ", error);
  }
}
