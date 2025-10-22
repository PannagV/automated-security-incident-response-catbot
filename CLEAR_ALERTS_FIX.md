# Clear Alerts Button Fix

## Problem
The "Clear Alerts" button in the Snort IDS frontend was not working.

## Root Cause
**Method name mismatch** in the backend:
- The API route `/snort/alerts/clear` was calling `snort_manager.clear_snort_alerts()`
- But the actual method in the `SnortManager` class is named `clear_alerts()`

This caused a `AttributeError` when the button was clicked.

## Fix Applied

### File: `snort_backend.py` (Line 782-785)

**Before:**
```python
@app.route('/snort/alerts/clear', methods=['DELETE'])
def clear_snort_alerts():
    result = snort_manager.clear_snort_alerts()  # ❌ Wrong method name
    return jsonify(result)
```

**After:**
```python
@app.route('/snort/alerts/clear', methods=['DELETE'])
def clear_snort_alerts():
    result = snort_manager.clear_alerts()  # ✅ Correct method name
    return jsonify(result)
```

## How It Works Now

1. User clicks "Clear Alerts" button in the frontend
2. Frontend shows confirmation dialog: "Clear all Snort alerts?"
3. If confirmed, sends DELETE request to `http://127.0.0.1:5001/snort/alerts/clear`
4. Backend calls `snort_manager.clear_alerts()`
5. Method clears both `alerts` and `snort_errors` lists
6. Returns `{"status": "success", "message": "Alerts and errors cleared"}`
7. Frontend updates UI and removes all alerts from display

## Testing

To test the fix:
1. Restart the Snort backend: `sudo python snort_backend.py`
2. Go to the Snort IDS page in the frontend
3. Generate some alerts (or wait for existing alerts)
4. Click the "Clear Alerts" button
5. Confirm the action
6. ✅ All alerts should be cleared immediately

## What Gets Cleared

The `clear_alerts()` method clears:
- ✅ All stored alerts (`self.alerts = []`)
- ✅ All Snort errors (`self.snort_errors = []`)
- ✅ Frontend alert display (via state update)

The button is now fully functional!