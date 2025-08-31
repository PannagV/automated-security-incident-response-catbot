import React, { useState, useEffect, useRef } from 'react';
import { useDarkMode } from '../contexts/DarkModeContext';

const SnortIDS = () => {
    const { isDarkMode } = useDarkMode();
    const [snortStatus, setSnortStatus] = useState({ status: 'stopped' });
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [filterSeverity, setFilterSeverity] = useState('all');
    const alertsEndRef = useRef(null);
    
    // Stats
    const [stats, setStats] = useState({
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    });

    useEffect(() => {
        fetchSnortStatus();
        fetchAlerts();
        
        // Set up auto-refresh
        const interval = setInterval(() => {
            if (autoRefresh) {
                fetchSnortStatus();
                fetchAlerts();
            }
        }, 2000);

        return () => clearInterval(interval);
    }, [autoRefresh]);

    useEffect(() => {
        // Calculate stats when alerts change
        const newStats = {
            total: alerts.length,
            critical: alerts.filter(a => a.severity === 'Critical').length,
            high: alerts.filter(a => a.severity === 'High').length,
            medium: alerts.filter(a => a.severity === 'Medium').length,
            low: alerts.filter(a => a.severity === 'Low').length
        };
        setStats(newStats);

        // Auto-scroll to bottom when new alerts arrive
        if (alertsEndRef.current && autoRefresh) {
            alertsEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [alerts, autoRefresh]);
            // Add this state to your SnortIDS component
        const [availableInterfaces, setAvailableInterfaces] = useState([]);
        const [selectedInterface, setSelectedInterface] = useState('');

        // Add this useEffect to fetch interfaces
        useEffect(() => {
            fetchAvailableInterfaces();
        }, []);

        const fetchAvailableInterfaces = async () => {
            try {
                const response = await fetch('http://127.0.0.1:5001/snort/interfaces');
                if (response.ok) {
                    const data = await response.json();
                    setAvailableInterfaces(data.interfaces);
                    setSelectedInterface(data.selected_interface);
                }
            } catch (err) {
                console.error('Error fetching interfaces:', err);
            }
        };

        const handleInterfaceChange = async (interfaceId) => {
            try {
                const response = await fetch(`http://127.0.0.1:5001/snort/interface/set/${interfaceId}`, {
                    method: 'POST'
                });
                if (response.ok) {
                    setSelectedInterface(interfaceId);
                    setError(null);
                }
            } catch (err) {
                setError('Failed to set interface');
            }
        };

        // Add this interface selection section to your control panel
        <div className="card-body">
            <div className="row mb-3">
                <div className="col-md-6">
                    <label className="form-label">Network Interface</label>
                    <select 
                        className="form-select"
                        value={selectedInterface}
                        onChange={(e) => handleInterfaceChange(e.target.value)}
                        disabled={snortStatus.status === 'running'}
                    >
                        {availableInterfaces.map((iface) => (
                            <option key={iface.snort_number} value={iface.snort_number}>
                                Interface {iface.snort_number}: {iface.name} 
                                {iface.addresses.length > 0 && ` (${iface.addresses[0].ip})`}
                                {iface.is_up ? ' - UP' : ' - DOWN'}
                            </option>
                        ))}
                    </select>
                    <small className="text-muted">
                        Auto-detected primary interface: {selectedInterface}
                    </small>
                </div>
                <div className="col-md-6">
                    <button 
                        className="btn btn-outline-info"
                        onClick={fetchAvailableInterfaces}
                        disabled={loading}
                    >
                        <i className="bi bi-arrow-clockwise me-2"></i>
                        Refresh Interfaces
                    </button>
                </div>
            </div>
            
            {/* Existing control buttons */}
            <div className="d-flex flex-wrap gap-3 align-items-center">
                {/* Your existing start/stop buttons */}
            </div>
        </div>

    const fetchSnortStatus = async () => {
        try {
            const response = await fetch('http://127.0.0.1:5001/snort/status');
            if (response.ok) {
                const data = await response.json();
                setSnortStatus(data);
            }
        } catch (err) {
            console.error('Error fetching Snort status:', err);
        }
    };

    const fetchAlerts = async () => {
        try {
            const response = await fetch('http://127.0.0.1:5001/snort/alerts');
            if (response.ok) {
                const data = await response.json();
                setAlerts(data);
                setError(null);
            }
        } catch (err) {
            console.error('Error fetching alerts:', err);
            setError('Failed to fetch alerts');
        }
    };

    const startSnort = async () => {
        setLoading(true);
        try {
            const response = await fetch('http://127.0.0.1:5001/snort/start', {
                method: 'POST'
            });
            const result = await response.json();
            
            if (result.status === 'started' || result.status === 'already_running') {
                setSnortStatus({ status: 'running', ...result });
                setError(null);
            } else {
                setError(result.message);
            }
        } catch (err) {
            setError('Failed to start Snort: ' + err.message);
        }
        setLoading(false);
    };

    const stopSnort = async () => {
        setLoading(true);
        try {
            const response = await fetch('http://127.0.0.1:5001/snort/stop', {
                method: 'POST'
            });
            const result = await response.json();
            
            if (result.status === 'stopped' || result.status === 'killed') {
                setSnortStatus({ status: 'stopped' });
                setError(null);
            } else {
                setError(result.message);
            }
        } catch (err) {
            setError('Failed to stop Snort: ' + err.message);
        }
        setLoading(false);
    };

    const clearAlerts = async () => {
        if (!window.confirm('Clear all Snort alerts?')) return;
        
        try {
            const response = await fetch('http://127.0.0.1:5001/snort/alerts/clear', {
                method: 'DELETE'
            });
            if (response.ok) {
                setAlerts([]);
                setError(null);
            }
        } catch (err) {
            setError('Failed to clear alerts: ' + err.message);
        }
    };

    const getSeverityIcon = (severity) => {
        switch(severity) {
            case 'Critical': return <i className="bi bi-exclamation-triangle-fill text-danger"></i>;
            case 'High': return <i className="bi bi-exclamation-triangle text-warning"></i>;
            case 'Medium': return <i className="bi bi-info-circle text-info"></i>;
            case 'Low': return <i className="bi bi-check-circle text-success"></i>;
            default: return <i className="bi bi-question-circle text-secondary"></i>;
        }
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString();
    };

    const filteredAlerts = filterSeverity === 'all' 
        ? alerts 
        : alerts.filter(alert => alert.severity === filterSeverity);

    return (
        <div className="snort-ids-dashboard">
            {/* Header */}
            <div className="app-header mb-4">
                <div className="d-flex align-items-center justify-content-between">
                    <div>
                        <h1 className="mb-2">
                            <i className="bi bi-shield-check me-3"></i>
                            Snort Intrusion Detection System
                        </h1>
                        <p className="mb-0">Real-time network monitoring and threat detection</p>
                    </div>
                    <div className="d-flex align-items-center gap-3">
                        <div className={`status-indicator ${snortStatus.status === 'running' ? 'status-active' : ''}`}></div>
                        <span className={`badge ${snortStatus.status === 'running' ? 'bg-success' : 'bg-secondary'}`}>
                            {snortStatus.status === 'running' ? 'ACTIVE' : 'STOPPED'}
                        </span>
                    </div>
                </div>
            </div>

            {error && (
                <div className="alert alert-danger alert-dismissible fade show" role="alert">
                    <i className="bi bi-exclamation-triangle me-2"></i>
                    {error}
                    <button type="button" className="btn-close" onClick={() => setError(null)}></button>
                </div>
            )}

            <div className="row">
                {/* Control Panel */}
                <div className="col-12 mb-4">
                    <div className="card">
                        <div className="card-header">
                            <h5 className="mb-0">
                                <i className="bi bi-gear me-2"></i>
                                Control Panel
                            </h5>
                        </div>
                        <div className="card-body">
                            <div className="d-flex flex-wrap gap-3 align-items-center">
                                <button 
                                    className="btn btn-success"
                                    onClick={startSnort}
                                    disabled={loading || snortStatus.status === 'running'}
                                >
                                    <i className="bi bi-play-fill me-2"></i>
                                    Start Snort
                                </button>
                                
                                <button 
                                    className="btn btn-danger"
                                    onClick={stopSnort}
                                    disabled={loading || snortStatus.status !== 'running'}
                                >
                                    <i className="bi bi-stop-fill me-2"></i>
                                    Stop Snort
                                </button>

                                <button 
                                    className="btn btn-outline-warning"
                                    onClick={clearAlerts}
                                    disabled={alerts.length === 0}
                                >
                                    <i className="bi bi-trash me-2"></i>
                                    Clear Alerts
                                </button>

                                <div className="form-check form-switch">
                                    <input 
                                        className="form-check-input" 
                                        type="checkbox" 
                                        id="autoRefresh"
                                        checked={autoRefresh}
                                        onChange={(e) => setAutoRefresh(e.target.checked)}
                                    />
                                    <label className="form-check-label" htmlFor="autoRefresh">
                                        Auto Refresh
                                    </label>
                                </div>

                                {snortStatus.interface && (
                                    <span className="badge bg-info">
                                        Interface: {snortStatus.interface}
                                    </span>
                                )}

                                {snortStatus.pid && (
                                    <span className="badge bg-secondary">
                                        PID: {snortStatus.pid}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
                // Add error display section
                {snortStatus.errors && snortStatus.errors.length > 0 && (
                    <div className="col-12 mb-4">
                        <div className="card border-danger">
                            <div className="card-header bg-danger text-white">
                                <h5 className="mb-0">
                                    <i className="bi bi-exclamation-triangle me-2"></i>
                                    Snort Errors
                                </h5>
                            </div>
                            <div className="card-body">
                                {snortStatus.errors.map((error, index) => (
                                    <div key={index} className="alert alert-danger mb-2">
                                        <strong>Time:</strong> {new Date(error.timestamp).toLocaleString()}<br/>
                                        <strong>Message:</strong> {error.message}<br/>
                                        {error.stderr && (
                                            <>
                                                <strong>Error:</strong> <pre className="mt-2">{error.stderr}</pre>
                                            </>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}
                {/* Statistics */}
                <div className="col-12 mb-4">
                    <div className="card">
                        <div className="card-header">
                            <h5 className="mb-0">
                                <i className="bi bi-graph-up me-2"></i>
                                Alert Statistics
                            </h5>
                        </div>
                        <div className="card-body">
                            <div className="row">
                                <div className="col-md-2 col-6 mb-3">
                                    <div className="stats-box text-center">
                                        <div className="stats-value text-primary">{stats.total}</div>
                                        <div className="stats-label">Total</div>
                                    </div>
                                </div>
                                <div className="col-md-2 col-6 mb-3">
                                    <div className="stats-box text-center">
                                        <div className="stats-value text-danger">{stats.critical}</div>
                                        <div className="stats-label">Critical</div>
                                    </div>
                                </div>
                                <div className="col-md-2 col-6 mb-3">
                                    <div className="stats-box text-center">
                                        <div className="stats-value text-warning">{stats.high}</div>
                                        <div className="stats-label">High</div>
                                    </div>
                                </div>
                                <div className="col-md-2 col-6 mb-3">
                                    <div className="stats-box text-center">
                                        <div className="stats-value text-info">{stats.medium}</div>
                                        <div className="stats-label">Medium</div>
                                    </div>
                                </div>
                                <div className="col-md-2 col-6 mb-3">
                                    <div className="stats-box text-center">
                                        <div className="stats-value text-success">{stats.low}</div>
                                        <div className="stats-label">Low</div>
                                    </div>
                                </div>
                                <div className="col-md-2 col-6 mb-3">
                                    <div className="stats-box text-center">
                                        <div className={`stats-value ${snortStatus.status === 'running' ? 'text-success' : 'text-secondary'}`}>
                                            {snortStatus.status === 'running' ? 'ON' : 'OFF'}
                                        </div>
                                        <div className="stats-label">Status</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Alerts Table */}
                <div className="col-12">
                    <div className="card">
                        <div className="card-header">
                            <div className="d-flex justify-content-between align-items-center">
                                <h5 className="mb-0">
                                    <i className="bi bi-list-ul me-2"></i>
                                    Real-time Alerts ({filteredAlerts.length})
                                </h5>
                                <select 
                                    className="form-select" 
                                    style={{ width: 'auto' }}
                                    value={filterSeverity}
                                    onChange={(e) => setFilterSeverity(e.target.value)}
                                >
                                    <option value="all">All Severities</option>
                                    <option value="Critical">Critical</option>
                                    <option value="High">High</option>
                                    <option value="Medium">Medium</option>
                                    <option value="Low">Low</option>
                                </select>
                            </div>
                        </div>
                        <div className="card-body">
                            {filteredAlerts.length > 0 ? (
                                <div className="table-responsive" style={{ maxHeight: '600px', overflowY: 'auto' }}>
                                    <table className="table table-hover">
                                        <thead className="sticky-top">
                                            <tr>
                                                <th>Time</th>
                                                <th>Severity</th>
                                                <th>Message</th>
                                                <th>Protocol</th>
                                                <th>Source</th>
                                                <th>Destination</th>
                                                <th>Classification</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {filteredAlerts.map((alert) => (
                                                <tr key={alert.id} className="highlight-new">
                                                    <td className="text-nowrap small">
                                                        {formatTimestamp(alert.timestamp)}
                                                    </td>
                                                    <td>
                                                        <span className={`badge severity-${alert.severity}`}>
                                                            {getSeverityIcon(alert.severity)}
                                                            {alert.severity}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <span title={alert.raw_log} className="text-truncate d-inline-block" style={{ maxWidth: '300px' }}>
                                                            {alert.message}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <span className="badge bg-secondary">{alert.protocol}</span>
                                                    </td>
                                                    <td className="font-monospace small">{alert.source}</td>
                                                    <td className="font-monospace small">{alert.destination}</td>
                                                    <td>
                                                        <small className="text-muted">{alert.classification}</small>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                    <div ref={alertsEndRef} />
                                </div>
                            ) : (
                                <div className="text-center py-5">
                                    <i className="bi bi-shield-check display-1 text-muted"></i>
                                    <h4 className="text-muted mt-3">No Alerts Detected</h4>
                                    <p className="text-muted">
                                        {snortStatus.status === 'running' 
                                            ? 'Snort is monitoring your network. Alerts will appear here when detected.'
                                            : 'Start Snort to begin monitoring your network for threats.'
                                        }
                                    </p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
    );
};

export default SnortIDS;
