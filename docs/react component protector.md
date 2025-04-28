# Nehonix Security Booster (NSB) - DOM & Request Analysis

## Overview

The NSB DOM & Request Analysis feature enhances web application security by adding real-time scanning of DOM elements and network requests. This feature builds upon the existing Nehonix Security Booster framework to detect and block malicious content before it reaches the user.

## Features
- **DOM Analysis**: Scan the document object model for malicious patterns
- **Request Monitoring**: Analyze network requests in real-time
- **Automatic Protection**: Components for easy integration of security features
- **Blocking Capability**: Optionally block and alert on malicious content
- **Developer Controls**: Toggle security features and access analysis results

## Quick Start

Wrap your application in the `NehonixShieldProvider` to enable security features:

```jsx
import { NehonixShieldProvider } from "nehonix-uri-processor";

function App() {
  return (
    <NehonixShieldProvider autoBlocking={true}>
      <YourApplication />
    </NehonixShieldProvider>
  );
}
```

## Core Components

### NehonixShieldProvider

The main provider component that makes security features available to your application.

```jsx
<NehonixShieldProvider
  defaultOptions={{ sensitivityLevel: "high" }}
  autoBlocking={true}
>
  {children}
</NehonixShieldProvider>
```

Props:

- `defaultOptions`: Default options for security analysis
- `autoBlocking`: Whether to block malicious content by default

### NehonixProtector

All-in-one protection component that enables both DOM and request analysis.

```jsx
<NehonixProtector
  domOptions={{ includeScripts: true, scanIframes: true }}
  requestOptions={{ includeFetch: true, includeXHR: true }}
  domInterval={60000} // Re-scan DOM every minute
>
  <UserGeneratedContent />
</NehonixProtector>
```

Props:

- `domOptions`: Options for DOM analysis
- `requestOptions`: Options for request analysis
- `domInterval`: Interval in milliseconds for periodic DOM scanning (null for no periodic scanning)

### NehonixDomProtector

Component that provides automatic DOM protection.

```jsx
<NehonixDomProtector
  options={{
    includeScripts: true,
    includeAttributes: true,
    includeLinks: true,
    scanIframes: false,
    targetSelector: "#user-content",
  }}
  interval={30000} // Re-scan every 30 seconds
>
  <UserContent />
</NehonixDomProtector>
```

Props:

- `options`: DOM analysis options
- `interval`: Interval in milliseconds for periodic scanning

### RequestProtector

Component that monitors network requests.

```jsx
<RequestProtector
  options={{
    includeXHR: true,
    includeFetch: true,
    includeImages: false,
    includeScripts: true,
    blockOnMalicious: true,
  }}
>
  <DynamicContent />
</RequestProtector>
```

Props:

- `options`: Request analysis options

## Hook API

The `useNehonixShield` hook provides access to security features within functional components:

```jsx
import { useNehonixShield } from "nehonix-uri-processor";

function SecureComponent() {
  const {
    analyzeDom,
    analyzeRequests,
    stopRequestAnalysis,
    blockingEnabled,
    setBlockingEnabled,
    lastAnalysisResult,
    isAnalyzing,
  } = useNehonixShield();

  // Use security features here
  return (
    <div>
      <button
        onClick={() => analyzeDom({ includeScripts: true })}
        disabled={isAnalyzing}
      >
        Scan Now
      </button>

      <button onClick={() => setBlockingEnabled(!blockingEnabled)}>
        {blockingEnabled ? "Disable" : "Enable"} Blocking
      </button>

      {lastAnalysisResult?.isMalicious && (
        <div className="alert alert-danger">Malicious content detected!</div>
      )}
    </div>
  );
}
```

## HOC (Higher-Order Component)

Use the `withDomAnalysis` HOC to add automatic DOM analysis to any component:

```jsx
import { withDomAnalysis } from "nehonix-uri-processor";

function UserContent({ nsbIsAnalyzing, nsbAnalysisResult, ...props }) {
  // The HOC injects these props
  return (
    <div>
      {nsbIsAnalyzing ? (
        <div>Scanning content...</div>
      ) : (
        <div>{props.content}</div>
      )}

      {nsbAnalysisResult?.isMalicious && (
        <div className="warning">Security issue detected!</div>
      )}
    </div>
  );
}

// Add DOM analysis with options
export default withDomAnalysis(UserContent, {
  includeScripts: true,
  targetSelector: "#user-content",
});
```

## API Reference

### DOM Analysis Options

| Option              | Type    | Default | Description                                          |
| ------------------- | ------- | ------- | ---------------------------------------------------- |
| `targetSelector`    | string  | 'body'  | CSS selector for the DOM element to analyze          |
| `includeAttributes` | boolean | true    | Whether to analyze HTML attributes                   |
| `includeScripts`    | boolean | true    | Whether to analyze script content                    |
| `includeLinks`      | boolean | true    | Whether to analyze href and src attributes           |
| `scanIframes`       | boolean | false   | Whether to analyze iframe content (same-origin only) |

### Request Analysis Options

| Option             | Type    | Default         | Description                                |
| ------------------ | ------- | --------------- | ------------------------------------------ |
| `includeXHR`       | boolean | true            | Whether to analyze XMLHttpRequest requests |
| `includeFetch`     | boolean | true            | Whether to analyze fetch requests          |
| `includeImages`    | boolean | false           | Whether to analyze image requests          |
| `includeScripts`   | boolean | true            | Whether to analyze script requests         |
| `blockOnMalicious` | boolean | (from provider) | Whether to block malicious requests        |

### Hook Methods

| Method                                    | Description                                           |
| ----------------------------------------- | ----------------------------------------------------- |
| `analyzeDom(options)`                     | Analyzes the DOM with the specified options           |
| `analyzeRequests(options)`                | Starts monitoring requests with the specified options |
| `stopRequestAnalysis()`                   | Stops monitoring requests                             |
| `scanUrl(url, options)`                   | Analyzes a specific URL                               |
| `scanInput(input, options)`               | Analyzes user input                                   |
| `provideFeedback(url, result, isCorrect)` | Provides feedback on analysis results                 |
| `getPerformanceMetrics()`                 | Returns performance metrics for the security analyzer |

### Hook Properties

| Property                      | Description                                  |
| ----------------------------- | -------------------------------------------- |
| `blockingEnabled`             | Whether blocking is currently enabled        |
| `setBlockingEnabled(enabled)` | Function to enable/disable blocking          |
| `lastAnalysisResult`          | The result of the most recent analysis       |
| `isAnalyzing`                 | Whether an analysis is currently in progress |

## Analysis Result Structure

Analysis results follow this structure:

```typescript
interface MaliciousPatternResult {
  isMalicious: boolean;
  detectedPatterns: Array<{
    type: string;
    matchedValue: string;
    location: string;
    severity: string;
  }>;
  score: number;
  confidence: "low" | "medium" | "high";
  recommendation: string;
  contextAnalysis: {
    relatedPatterns: string[];
    entropyScore: number;
    anomalyScore: number;
    encodingLayers: number;
  };
}
```

## Example Use Cases

### Securing User-Generated Content

```jsx
function UserContentViewer({ content }) {
  return (
    <NehonixDomProtector
      options={{
        includeScripts: true,
        includeLinks: true,
      }}
    >
      <div dangerouslySetInnerHTML={{ __html: content }} />
    </NehonixDomProtector>
  );
}
```

### Monitoring API Calls

```jsx
function DataFetcher() {
  const fetchData = async () => {
    // All API calls made here will be monitored
  };

  return (
    <RequestProtector options={{ includeXHR: true, includeFetch: true }}>
      <button onClick={fetchData}>Fetch Data</button>
      <div id="results"></div>
    </RequestProtector>
  );
}
```

### Implementing a Security Dashboard

```jsx
function SecurityDashboard() {
  const {
    analyzeDom,
    analyzeRequests,
    stopRequestAnalysis,
    lastAnalysisResult,
    blockingEnabled,
    setBlockingEnabled,
  } = useNehonixShield();

  return (
    <div className="dashboard">
      <h2>Security Controls</h2>

      <div className="control-panel">
        <button onClick={() => analyzeDom()}>Scan DOM Now</button>

        <button onClick={() => analyzeRequests()}>
          Start Request Monitoring
        </button>

        <button onClick={stopRequestAnalysis}>Stop Request Monitoring</button>

        <label>
          <input
            type="checkbox"
            checked={blockingEnabled}
            onChange={(e) => setBlockingEnabled(e.target.checked)}
          />
          Block Malicious Content
        </label>
      </div>

      <div className="results-panel">
        <h3>Last Analysis Result</h3>
        {lastAnalysisResult ? (
          <pre>{JSON.stringify(lastAnalysisResult, null, 2)}</pre>
        ) : (
          <p>No analysis performed yet</p>
        )}
      </div>
    </div>
  );
}
```

## Best Practices

1. **Balance Security and Performance**: DOM scanning can be resource-intensive. Use targeted selectors and reasonable intervals.

2. **Layer Security**: Use multiple protection strategies together for comprehensive security.

3. **Handle False Positives**: Implement override mechanisms for cases where legitimate content is flagged.

4. **Inform Users**: Notify users when content is blocked and provide clear explanations.

5. **Regular Updates**: Keep the security library updated to protect against new threats.

## Browser Compatibility

The DOM and Request Analysis features are compatible with all modern browsers that support:

- MutationObserver
- PerformanceObserver
- Fetch API
- Web Notifications API

Internet Explorer is not supported.

## Contributing

Contributions are welcome! Please see our [contributing guidelines](../CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
