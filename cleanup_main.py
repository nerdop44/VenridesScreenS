
import sys

filename = "/home/nerdop/VenridesScreenS/backend/main.py"
try:
    with open(filename, "r") as f:
        lines = f.readlines()
        
    # Target lines: 3235 to 3433 (1-based)
    # Indices: 3234 to 3432 (0-based)
    start_idx = 3234
    end_idx = 3433 # Python slice end is exclusive, so 3433 will remove up to index 3432
    
    # Verify content to be sure
    if "# --- DEFAULT TEMPLATE HTML CONTENT" not in lines[start_idx]:
        print(f"Error: Line {start_idx+1} does not match expected start.")
        print(f"Content: {lines[start_idx]}")
        sys.exit(1)
        
    if "]" not in lines[end_idx-1]: # Check last line to be removed (index 3432)
        print(f"Error: Line {end_idx} does not match expected end.")
        print(f"Content: {lines[end_idx-1]}")
        sys.exit(1)
        
    print(f"Removing lines {start_idx+1} to {end_idx}...")
    new_lines = lines[:start_idx] + lines[end_idx:]
    
    with open(filename, "w") as f:
        f.writelines(new_lines)
        
    print("Success.")
    
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
