import React, { useEffect, useState, useRef } from 'react';
import io from 'socket.io-client';
import './LiveAlertMonitor.css';

const SuricataLogMonitor = () => {
    const [alerts, setAlerts] = useState([]);
    const [isConnected, setIsConnected] = useState(false);
    const [alertStats, setAlertStats] = useState({
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    });
    const [autoScroll, setAutoScroll] = useState(true);
    const [filter, setFilter] = useState('all');
    const [suricataStatus, setSuricataStatus] = useState('unknown'); // unknown, running, stopped, error
    const terminalRef = useRef(null);

    // --- API Communication ---
    const API_BASE_URL = 'http://localhost:5000/api/suricata';

    const getStatus = async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/status`);
            const data = await response.json();
            if (data.suricata_running) {
                setSuricataStatus('running');
            } else {
                setSuricataStatus('stopped');
            }
        } catch (error) {
            console.error('Failed to get Suricata status:', error);
            setSuricataStatus('error');
            addSystemMessage('Error: Could not connect to backend to get IDS status.');
        }
    };

    const startIDS = async () => {
        if (suricataStatus === 'running') return;
        addSystemMessage('Attempting to start Suricata IDS...');
        setSuricataStatus('starting');
        try {
            const response = await fetch(`${API_BASE_URL}/start`, { method: 'POST' });
            const data = await response.json();
            if (data.status === 'success' || data.status === 'already_running') {
                addSystemMessage('Suricata IDS started successfully.');
                setSuricataStatus('running');
            } else {
                throw new Error(data.message || 'Unknown error');
            }
        } catch (error) {
            console.error('Failed to start Suricata:', error);
            addSystemMessage(`Error starting IDS: ${error.message}`);
            setSuricataStatus('error');
        }
    };

    const stopIDS = async () => {
        if (suricataStatus !== 'running') return;
        addSystemMessage('Attempting to stop Suricata IDS...');
        setSuricataStatus('stopping');
        try {
            const response = await fetch(`${API_BASE_URL}/stop`, { method: 'POST' });
            const data = await response.json();
            if (data.status === 'success' || data.status === 'not_running') {
                addSystemMessage('Suricata IDS stopped successfully.');
                setSuricataStatus('stopped');
            } else {
                throw new Error(data.message || 'Unknown error');
            }
        } catch (error) {
            console.error('Failed to stop Suricata:', error);
            addSystemMessage(`Error stopping IDS: ${error.message}`);
            setSuricataStatus('error');
        }
    };


    useEffect(() => {
        // Add initial welcome messages
        addWelcomeMessages();
        
        // Fetch initial logs and status
        getStatus();
        fetchInitialLogs();

        // Connect to WebSocket for real-time updates
        const socket = io('http://localhost:5000');

        socket.on('connect', () => {
            setIsConnected(true);
            console.log('Connected to Suricata alert stream');
            addSystemMessage('Connected to Suricata IDS monitoring system');
        });

        socket.on('disconnect', () => {
            setIsConnected(false);
            console.log('Disconnected from Suricata alert stream');
            addSystemMessage('Disconnected from monitoring system');
        });

        socket.on('suricata_alert', (alert) => {
            setAlerts(prev => {
                const newAlerts = [alert, ...prev].slice(0, 1000); // Keep last 1000 alerts
                updateStats(newAlerts);
                return newAlerts;
            });
        });

        // Periodically check status
        const statusInterval = setInterval(getStatus, 10000); // every 10 seconds

        return () => {
            socket.disconnect();
            clearInterval(statusInterval);
        };
    }, []);

    // Auto-scroll to bottom when new alerts arrive
    useEffect(() => {
        if (autoScroll && terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [alerts, autoScroll]);

    const addWelcomeMessages = () => {
        const welcomeMessages = [
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '========================================',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            },
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '    SURICATA LOG MONITOR v2.0',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            },
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '    Real-time IDS Alert Monitoring',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            },
            {
                timestamp: new Date().toISOString(),
                severity: 'System',
                signature: '========================================',
                source_ip: 'System',
                dest_ip: '-',
                source_port: '-',
                dest_port: '-',
                protocol: '-',
                category: 'System',
                rule_file: 'system.log'
            }
        ];
        setAlerts(welcomeMessages);
    };

    const addSystemMessage = (message) => {
        const systemAlert = {
            timestamp: new Date().toISOString(),
            severity: 'System',
            signature: message,
            source_ip: 'System',
            dest_ip: '-',
            source_port: '-',
            dest_port: '-',
            protocol: '-',
            category: 'System',
            rule_file: 'system.log'
        };
        setAlerts(prev => [systemAlert, ...prev]);
    };

    const fetchInitialLogs = async () => {
        try {
            addSystemMessage('Initializing Suricata log monitor...');
            const response = await fetch('http://localhost:5000/api/suricata/logs');
            const data = await response.json();
            if (data.status === 'success') {
                const initialAlerts = data.logs.slice(0, 100); // Limit initial display
                setAlerts(prev => [...initialAlerts, ...prev]);
                updateStats(initialAlerts);
                addSystemMessage(`Loaded ${initialAlerts.length} previous alerts.`);
            } else {
                addSystemMessage(`Warning: Could not fetch initial logs: ${data.message}`);
            }
        } catch (error) {
            addSystemMessage(`Error fetching initial logs: ${error.message}`);
        }
    };

    const updateStats = (alertList) => {
        const stats = {
            total: alertList.filter(a => a.severity !== 'System').length,
            critical: alertList.filter(a => a.severity === 'Critical').length,
            high: alertList.filter(a => a.severity === 'High').length,
            medium: alertList.filter(a => a.severity === 'Medium').length,
            low: alertList.filter(a => a.severity === 'Low').length
        };
        setAlertStats(stats);
    };

    const getSeverityColor = (severity) => {
        switch(severity) {
            case 'Critical': return '#ff4444';
            case 'High': return '#ff8c00';
            case 'Medium': return '#ffd700';
            case 'Low': return '#00ff00';
            case 'System': return '#00bfff';
            default: return '#ffffff';
        }
    };

    const getSeverityPrefix = (severity) => {
        switch(severity) {
            case 'Critical': return '[CRIT]';
            case 'High': return '[HIGH]';
            case 'Medium': return '[MED ]';
            case 'Low': return '[LOW ]';
            case 'System': return '[SYS ]';
            default: return '[INFO]';
        }
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString('en-US', {
            hour12: false,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const formatLogEntry = (alert) => {
        if (alert.severity === 'System') {
            // For welcome messages and system messages, display them specially
            if (alert.signature.includes('SURICATA LOG MONITOR') || 
                alert.signature.includes('Real-time IDS') ||
                alert.signature.includes('====')) {
                return alert.signature;
            }
            return `${formatTimestamp(alert.timestamp)} ${getSeverityPrefix(alert.severity)} ${alert.signature}`;
        }
        
        return `${formatTimestamp(alert.timestamp)} ${getSeverityPrefix(alert.severity)} [${alert.protocol}] ${alert.source_ip}:${alert.source_port} -> ${alert.dest_ip}:${alert.dest_port} | ${alert.signature} | Category: ${alert.category}`;
    };

    const filteredAlerts = alerts.filter(alert => {
        if (filter === 'all') return true;
        if (filter === 'system') return alert.severity === 'System';
        return alert.severity.toLowerCase() === filter.toLowerCase();
    });

    const clearTerminal = () => {
        setAlerts([]);
        setAlertStats({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
        addWelcomeMessages();
        addSystemMessage('Terminal cleared');
    };

    return (
        <div className="terminal-wrapper">
            <div className="terminal-container">
                <div className="terminal-header">
                    <div className="terminal-buttons">
                        <span className="terminal-button close"></span>
                        <span className="terminal-button minimize"></span>
                        <span className="terminal-button maximize"></span>
                    </div>
                    <div className="terminal-title-text">Suricata IDS - Live Monitor</div>
                    <div className="terminal-status">
                        <span className={`connection-indicator ${isConnected ? 'connected' : 'disconnected'}`}></span>
                        {isConnected ? 'Connected' : 'Disconnected'}
                    </div>
                </div>

                <div className="terminal-controls-bar">
                    <div className="stats-bar">
                        <div className={`stat-item total`}>Total: {alertStats.total}</div>
                        <div className={`stat-item critical`}>Critical: {alertStats.critical}</div>
                        <div className={`stat-item high`}>High: {alertStats.high}</div>
                        <div className={`stat-item medium`}>Medium: {alertStats.medium}</div>
                        <div className={`stat-item low`}>Low: {alertStats.low}</div>
                    </div>
                    <div className="terminal-actions">
                        <button 
                            className="terminal-btn start" 
                            onClick={startIDS}
                            disabled={suricataStatus === 'running' || suricataStatus === 'starting'}
                        >
                            Start IDS
                        </button>
                        <button 
                            className="terminal-btn stop"
                            onClick={stopIDS}
                            disabled={suricataStatus !== 'running'}
                        >
                            Stop IDS
                        </button>
                        <button className="terminal-btn clear" onClick={clearTerminal}>Clear</button>
                        <label className="autoscroll-label">
                            <input
                                type="checkbox"
                                checked={autoScroll}
                                onChange={(e) => setAutoScroll(e.target.checked)}
                            />
                            Auto-Scroll
                        </label>
                    </div>
                </div>

                <div className="terminal-body" ref={terminalRef}>
                    {filteredAlerts.length === 0 ? (
                        <div className="terminal-empty">
                            <p>No alerts to display. Start the IDS to begin monitoring.</p>
                        </div>
                    ) : (
                        filteredAlerts.map((alert, index) => (
                            <div key={index} className={`terminal-line ${getSeverityColor(alert.severity)}`}>
                                {formatLogEntry(alert)}
                            </div>
                        ))
                    )
                    }
                    <div className="terminal-cursor"></div>
                </div>
            </div>
        </div>
    );
};

export default SuricataLogMonitor;
