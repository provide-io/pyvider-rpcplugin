# Logging Architecture

## stderr-Only Principle

**pyvider-rpcplugin is a LIBRARY** and follows the principle that **libraries MUST ONLY log to stderr**.

### Why stderr-Only?

1. **stdout is for program output** - Applications use stdout for data output that other programs consume
2. **stderr is for diagnostics** - Logs, errors, warnings, and debug information belong on stderr
3. **Libraries must not pollute stdout** - If a library writes to stdout, it breaks pipelines and data processing

### Implementation

All logging in pyvider-rpcplugin uses Foundation's logger system:

```python
from provide.foundation.logger import get_logger

logger = get_logger(__name__)  # Creates module-specific logger
logger.info("This goes to stderr automatically")
```

**Foundation's logger writes to stderr by default** - no configuration needed.

### What NOT to Use

❌ **NEVER use `print()` in library code** - `print()` writes to stdout by default
❌ **NEVER write directly to `sys.stdout`** - This pollutes the output stream
❌ **Don't use `pout()`** - This is for application output, not library logging

### What to Use

✅ **Use `logger.debug/info/warning/error()`** - Always goes to stderr
✅ **Use structured logging with keyword args** - `logger.info("Message", key=value)`
✅ **Use `perr()` if you need direct stderr output** - Rare, but available

### For Applications vs Libraries

| Component | stdout | stderr | logger |
|-----------|---------|---------|---------|
| **Library** (pyvider-rpcplugin) | ❌ Never | ✅ Always | ✅ Yes (stderr) |
| **Application** (demos, tests) | ✅ Program output | ✅ Logs/errors | ✅ Yes (stderr) |

### Example

```python
# ❌ BAD - Library code writing to stdout
def process_data():
    print("Processing...")  # Pollutes stdout!
    return data

# ✅ GOOD - Library code logging to stderr
from provide.foundation.logger import get_logger

logger = get_logger(__name__)

def process_data():
    logger.debug("Processing data...")  # Goes to stderr
    return data
```

### Verification

To verify logs go to stderr, run:

```bash
# Logs should appear even when stdout is redirected
python my_script.py > /dev/null  # Logs still visible on console (stderr)

# Capture logs separately from output
python my_script.py 2> logs.txt  # Logs to file, output to console
```

## See Also

- `provide.foundation.logger` - Foundation's logging system
- `provide.foundation.console` - For stdin/stdout/stderr when needed (`pin`, `pout`, `perr`)
