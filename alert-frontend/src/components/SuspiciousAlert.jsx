import React from 'react';
import './SuspiciousAlert.css';

const SuspiciousAlert = ({ message, timestamp, details }) => {
    return (
        <div className="suspicious-alert">
            <span className="suspicious-alert-icon">⚠️</span>
            <div className="suspicious-alert-content">
                <div>{message}</div>
                {details && <div className="suspicious-alert-details">{details}</div>}
                <div className="suspicious-alert-timestamp">
                    {new Date(timestamp).toLocaleString()}
                </div>
            </div>
        </div>
    );
};

export default SuspiciousAlert;
