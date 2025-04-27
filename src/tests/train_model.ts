import { spawn } from "child_process";
import path from "path";
import fs from "fs";

// Configuration
const MODEL_DIR = "./microservices/models";
const PYTHON_PATH = "python";
const MODEL_SCRIPT = "./microservices/nehonix.shield_model.py";
// Ensure the directory exists
if (!fs.existsSync(MODEL_DIR)) {
  fs.mkdirSync(MODEL_DIR, { recursive: true });
  console.log(`Created directory: ${MODEL_DIR}`);
}

// Debugging function to save output to file
function saveOutputToFile(content: string, filename: string) {
  const outputPath = path.join(MODEL_DIR, filename);
  fs.writeFileSync(outputPath, content);
  console.log(`Saved output to ${outputPath}`);
}

// Test running a simple command
function testPythonExecution() {
  console.log("Testing Python execution...");
  console.log(`Python script path: ${MODEL_SCRIPT}`);

  // Check if script exists
  if (!fs.existsSync(MODEL_SCRIPT)) {
    console.error(`ERROR: Script not found at ${MODEL_SCRIPT}`);
    console.log(`Current directory: ${__dirname}`);
    return;
  }

  console.log("Script file exists. Testing execution...");

  // Run a simple Python command to check if Python works
  const pythonVersionProcess = spawn(PYTHON_PATH, ["--version"]);

  pythonVersionProcess.stdout.on("data", (data) => {
    console.log(`Python version stdout: ${data}`);
  });

  pythonVersionProcess.stderr.on("data", (data) => {
    console.log(`Python version stderr: ${data}`);
  });

  pythonVersionProcess.on("close", (code) => {
    console.log(`Python version process exited with code ${code}`);

    // Now try to execute the script with a simple command
    executeScriptTest();
  });
}

// Test executing the actual script
function executeScriptTest() {
  console.log("\nTesting ML script execution...");

  // Create a simple generate command with minimal data
  const testData = {
    command: "generate",
    num_samples: 10, // Just 10 samples for a quick test
    malicious_ratio: 0.5,
  };

  // Save the input we're sending for reference
  saveOutputToFile(JSON.stringify(testData, null, 2), "debug_input.json");

  // Spawn the process
  const pythonProcess = spawn(PYTHON_PATH, [MODEL_SCRIPT]);
  let stdoutData = "";
  let stderrData = "";

  // Send the data
  pythonProcess.stdin.write(JSON.stringify(testData));
  pythonProcess.stdin.end();

  // Collect all stdout data
  pythonProcess.stdout.on("data", (data) => {
    const chunk = data.toString();
    stdoutData += chunk;
    console.log(`Received stdout chunk (${chunk.length} bytes)`);
  });

  // Collect all stderr data
  pythonProcess.stderr.on("data", (data) => {
    const chunk = data.toString();
    stderrData += chunk;
    console.log(`Received stderr chunk: ${chunk}`);
  });

  // Process completion
  pythonProcess.on("close", (code) => {
    console.log(`Python process exited with code ${code}`);

    // Save the raw output
    saveOutputToFile(stdoutData, "debug_stdout.txt");
    saveOutputToFile(stderrData, "debug_stderr.txt");

    // Try to find JSON in the output
    console.log("\nAnalyzing stdout output:");
    if (stdoutData.trim().length === 0) {
      console.log("No stdout output received!");
    } else {
      console.log(`Total stdout length: ${stdoutData.length} bytes`);
      console.log("First 200 characters:");
      console.log(stdoutData.slice(0, 200));

      // Try to find JSON
      try {
        const jsonMatch = stdoutData.match(/({[\s\S]*}|\[[\s\S]*\])/);
        if (jsonMatch) {
          console.log("Found potential JSON object in the output");
          const jsonStr = jsonMatch[0];
          console.log("Trying to parse it...");
          const result = JSON.parse(jsonStr);
          console.log("Successfully parsed JSON:");
          console.log(JSON.stringify(result, null, 2).slice(0, 500) + "...");
        } else {
          console.log("No JSON-like patterns found in the output");
        }
      } catch (e) {
        console.log("Failed to find or parse JSON in the output", e);
      }
    }

    // Check for specific issues
    checkForCommonIssues(stdoutData, stderrData);
  });
}

// Check for common issues in the output
function checkForCommonIssues(stdout: string, stderr: string) {
  console.log("\nChecking for common issues:");

  // Check for Python tracebacks in stderr
  if (stderr.includes("Traceback")) {
    console.log("✖ Python error detected (traceback in stderr)");
    console.log("Possible issue: Python script has errors or exceptions");
    console.log(
      "Solution: Check the stderr output file and fix errors in ml_model.py"
    );
  }

  // Check for import errors
  if (
    stderr.includes("ImportError") ||
    stderr.includes("ModuleNotFoundError")
  ) {
    console.log("✖ Python module import error detected");
    console.log("Possible issue: Missing Python packages");
    console.log("Solution: Install required packages with pip");
  }

  // Check for file path issues
  if (
    stderr.includes("FileNotFoundError") ||
    stderr.includes("No such file or directory")
  ) {
    console.log("✖ File not found error detected");
    console.log("Possible issue: Incorrect file paths in Python script");
    console.log("Solution: Check paths in ml_model.py");
  }

  // Check for permission issues
  if (stderr.includes("PermissionError")) {
    console.log("✖ Permission error detected");
    console.log("Possible issue: No write access to output directories");
    console.log(
      "Solution: Run with appropriate permissions or change output directory"
    );
  }

  // Check for non-JSON output mixed with JSON
  if (stdout.includes("print(") || stdout.includes("console.log(")) {
    console.log("✖ Possible debug print statements detected");
    console.log("Possible issue: Debug output is mixed with JSON response");
    console.log(
      "Solution: Remove or comment out print statements in ml_model.py"
    );
  }

  // Check for encoding issues
  const nonAsciiRegex = /[^\x00-\x7F]/g;
  if (nonAsciiRegex.test(stdout)) {
    console.log("✖ Non-ASCII characters detected in output");
    console.log("Possible issue: Encoding problems in the output");
    console.log("Solution: Ensure proper encoding in Python script");
  }

  // Next steps
  console.log("\nNext steps:");
  console.log(
    "1. Examine debug_stdout.txt and debug_stderr.txt files in the models directory"
  );
  console.log("2. Fix any issues found in the ml_model.py script");
  console.log(
    "3. Try running the train_model.ts script again with --debug flag"
  );
}

// Main function
function main() {
  console.log("Starting Python interaction debug script");
  console.log("=======================================");

  // Run the tests
  testPythonExecution();
}

// Run the script
main();
