import { AlertProps } from "./provider.type";

const SecurityAlert: React.FC<AlertProps> = ({
  message,
  type,
  details,
  onDismiss,
  position,
}) => {
  // Set styles based on alert type
  const getBackgroundColor = () => {
    switch (type) {
      case "error":
        return "#f8d7da";
      case "warning":
        return "#fff3cd";
      case "info":
      default:
        return "#d1ecf1";
    }
  };

  const getBorderColor = () => {
    switch (type) {
      case "error":
        return "#f5c6cb";
      case "warning":
        return "#ffeeba";
      case "info":
      default:
        return "#bee5eb";
    }
  };

  const getTextColor = () => {
    switch (type) {
      case "error":
        return "#721c24";
      case "warning":
        return "#856404";
      case "info":
      default:
        return "#0c5460";
    }
  };

  // Position styles
  const getPositionStyle = () => {
    switch (position) {
      case "top-right":
        return { top: "20px", right: "20px" };
      case "top-left":
        return { top: "20px", left: "20px" };
      case "bottom-right":
        return { bottom: "20px", right: "20px" };
      case "bottom-left":
        return { bottom: "20px", left: "20px" };
      default:
        return { top: "20px", right: "20px" };
    }
  };

  const alertStyle: React.CSSProperties = {
    position: "fixed",
    zIndex: 9999,
    padding: "15px 20px",
    borderRadius: "4px",
    boxShadow: "0 4px 6px rgba(0, 0, 0, 0.1)",
    maxWidth: "400px",
    backgroundColor: getBackgroundColor(),
    borderLeft: `4px solid ${getBorderColor()}`,
    color: getTextColor(),
    fontSize: "14px",
    ...getPositionStyle(),
  };

  const headerStyle: React.CSSProperties = {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "5px",
  };

  const titleStyle: React.CSSProperties = {
    fontWeight: "bold",
    margin: 0,
  };

  const closeButtonStyle: React.CSSProperties = {
    background: "none",
    border: "none",
    cursor: "pointer",
    fontSize: "16px",
    color: getTextColor(),
    padding: "0",
    marginLeft: "10px",
  };

  const detailsStyle: React.CSSProperties = {
    marginTop: "10px",
    maxHeight: "150px",
    overflowY: "auto",
    fontSize: "12px",
  };

  const detailItemStyle: React.CSSProperties = {
    padding: "6px 8px",
    backgroundColor: "rgba(255, 255, 255, 0.7)",
    borderRadius: "3px",
    marginBottom: "5px",
  };

  return (
    <div style={alertStyle}>
      <div style={headerStyle}>
        <h4 style={titleStyle}>Security Alert</h4>
        <button style={closeButtonStyle} onClick={onDismiss}>
          ×
        </button>
      </div>
      <p>{message}</p>
      {details && details.length > 0 && (
        <div style={detailsStyle}>
          {details.map((pattern, index) => (
            <div key={index} style={detailItemStyle}>
              <strong>{pattern.type}</strong>: {pattern.matchedValue}
              <br />
              <small>Location: {pattern.location}</small>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SecurityAlert;
