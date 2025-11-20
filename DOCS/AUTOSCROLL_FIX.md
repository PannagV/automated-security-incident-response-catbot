# Auto-Scroll Toggle Added to Snort IDS Frontend

## Changes Made

### File: `alert-frontend/src/components/SnortIDS.jsx`

#### 1. Added Auto-Scroll State
```jsx
const [autoScroll, setAutoScroll] = useState(false); // Auto-scroll disabled by default
```

#### 2. Updated Auto-Scroll Logic
Changed from using `autoRefresh` to using dedicated `autoScroll` state:
```jsx
// Before:
if (alertsEndRef.current && autoRefresh) {
    alertsEndRef.current.scrollIntoView({ behavior: 'smooth' });
}

// After:
if (alertsEndRef.current && autoScroll) {
    alertsEndRef.current.scrollIntoView({ behavior: 'smooth' });
}
```

#### 3. Added Toggle Switch in UI
Added a new toggle switch next to the "Auto Refresh" toggle:
```jsx
<div className="form-check form-switch">
    <input 
        className="form-check-input" 
        type="checkbox" 
        id="autoScroll"
        checked={autoScroll}
        onChange={(e) => setAutoScroll(e.target.checked)}
    />
    <label className="form-check-label" htmlFor="autoScroll">
        Auto Scroll
    </label>
</div>
```

## How It Works

- **Auto Scroll OFF (default)**: The alerts list will stay at your current scroll position, allowing you to read alerts without the page jumping
- **Auto Scroll ON**: The page will automatically scroll to the latest alert when new alerts arrive

## Usage

1. In the Snort IDS page, look for the controls section
2. You'll see two toggles:
   - **Auto Refresh** - Controls automatic fetching of new alerts (every 2 seconds)
   - **Auto Scroll** - Controls whether the page automatically scrolls to new alerts

3. Toggle "Auto Scroll" OFF to stop the automatic scrolling behavior
4. You can still enable "Auto Refresh" to get new alerts without auto-scrolling

## Benefits

✅ **Better UX**: You can now read alerts without being interrupted by auto-scrolling
✅ **Separate Controls**: Auto-refresh and auto-scroll are independent features
✅ **Default OFF**: Auto-scroll is disabled by default to prevent annoyance
✅ **Smooth Experience**: When enabled, uses smooth scrolling behavior