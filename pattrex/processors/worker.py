import re
from concurrent.futures import ProcessPoolExecutor, as_completed

def _scan_chunk(chunk, pattern_strings, want_groups=False):
    try:
        compiled_patterns = [re.compile(p) for p in pattern_strings]
        results = []
        for line in chunk:
            for pat in compiled_patterns:
                for m in pat.finditer(line):
                    if want_groups:
                        results.append(m.groupdict() or m.groups())
                    else:
                        results.append(m.group(0))
        return results
    except Exception as e:
        return {"error": str(e)}

def parallel_scan(lines, pattern_strings, workers=4, want_groups=False):
    """
    Return list of matches from given patterns.
    """
    if not lines:
        return []

    chunk_size = max(1, len(lines) // workers)

    results = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = []
        for i in range(0, len(lines), chunk_size):
            chunk = lines[i:i + chunk_size]
            futures.append(executor.submit(_scan_chunk, chunk, pattern_strings, want_groups))

        for fut in as_completed(futures):
            try:
                res = fut.result()
                if isinstance(res, dict) and "error" in res:
                    print(f"Error in worker: {res['error']}")
                else:
                    results.extend(res)
            except Exception as e:
                print(f"Exception in future: {e}")

    return results

# Example usage:
if __name__ == "__main__":
    lines = ["foo 123", "bar 456", "baz 789"]
    patterns = [r"\d+"]
    matches = parallel_scan(lines, patterns, workers=2)
    print(matches)  # Output: ['123', '456', '789']