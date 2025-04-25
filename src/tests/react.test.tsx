import { useState } from "react";
import {
  NehonixShieldProvider,
  useNehonixShield,
  type MaliciousPatternResult,
  MaliciousPatternType,
} from "..";

const App: React.FC = () => {
  return (
    <NehonixShieldProvider defaultOptions={{ minScore: 50, sensitivity: 1.0 }}>
      <SecurityDemo />
    </NehonixShieldProvider>
  );
};

const SecurityDemo: React.FC = () => {
  const { analyzeUrl, provideFeedback, getPerformanceMetrics } =
    useNehonixShield();
  const [result, setResult] = useState<MaliciousPatternResult | null>(null);

  const handleAnalyze = async () => {
    const url = "https://malicious.com/login?obj[__proto__][polluted]=true";
    const analysis = await analyzeUrl(url, {
      ignorePatterns: [MaliciousPatternType.ANOMALY],
    });
    setResult(analysis);
    provideFeedback(url, analysis, true);
    console.log("Metrics:", getPerformanceMetrics());
  };

  return (
    <div>
      <button onClick={handleAnalyze}>Analyze URL</button>
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
};

export default App;
