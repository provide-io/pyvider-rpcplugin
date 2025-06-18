export ECHO_PLUGIN_MAGIC_COOKIE=standalonesecret
export PLUGIN_MAGIC_COOKIE_KEY=ECHO_PLUGIN_MAGIC_COOKIE # Correct key name
export PLUGIN_MAGIC_COOKIE_VALUE=standalonesecret # Expected value by server

# Run in insecure mode for this demo to bypass mTLS complexities with self-signed certs

# Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
export PLUGIN_LOG_LEVEL="INFO" # Matches CONFIG_SCHEMA key
