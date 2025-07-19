# This is the actual environment variable the client will read and send.
export PLUGIN_MAGIC_COOKIE="standalonesecret"

# This tells the server what value it should expect from the client.
export PLUGIN_MAGIC_COOKIE_VALUE="standalonesecret"

# Optional: If you want the client to look for a *different* environment variable
# than "PLUGIN_MAGIC_COOKIE", you'd set PLUGIN_MAGIC_COOKIE_KEY.
# But for this demo, relying on the default key "PLUGIN_MAGIC_COOKIE" is simpler.
# export PLUGIN_MAGIC_COOKIE_KEY="ECHO_PLUGIN_MAGIC_COOKIE" # Not strictly needed if client uses default key

# Run in insecure mode for this demo to bypass mTLS complexities with self-signed certs
# This will be overridden by client/server specific settings in the bash script for mTLS.
export PLUGIN_AUTO_MTLS="true"

# Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
export PLUGIN_LOG_LEVEL="INFO"
