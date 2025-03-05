import logging


class AlignedFormatter(logging.Formatter):
    MAX_NAME_WIDTH = 23  # Space allocated for module name truncation
    LEVEL_PADDING = 10  # Minimum space allocated for log level (adjust dynamically)

    # Define emoji prefixes for different log categories
    EMOJI_PREFIXES = {
        "core": "🐍🏗️ ",
        "injector": "🐍💉️",
        "resource": "🐍🔧",
        "schema": "📜🛠️ ",
        "capability": "🧰✨",
        "discovery": "🛰️ 🔍",
        "auth": "🔐🐍",
        "dynamic": "📦🔄",
        "lifecycle": "🌱🔄",
        "trace": "🛤 ️👀",
        "network": "🌐📡",
        "error": "🔥🐛",
        "performance": "⚡📈",
        "cli": "💻 ⚙️",
        "lock": "🔒🔄",
        "server": "🏗️ 🫴 ",
        "hub.components": "🧫🧩",
        "utils.crypto": "🔧🔏",
    }

    def format(self, record: logging.LogRecord) -> str:
        # Format timestamp
        timestamp = self.formatTime(record, self.datefmt)

        # Remove 'pyvider.' prefix from module name
        module_name = record.name.replace("pyvider.", "")

        # Truncate module name from the left if necessary
        if len(module_name) > self.MAX_NAME_WIDTH:
            module_name = f"{module_name[-(self.MAX_NAME_WIDTH - 0) :]}"
        else:
            module_name = module_name.rjust(self.MAX_NAME_WIDTH)

        # Calculate log level width dynamically (e.g., [TRACE999])
        log_level = f"[{record.levelname}]"
        dynamic_padding = max(len(log_level), self.LEVEL_PADDING)

        # Right-align the log level based on the widest entry
        level = log_level.rjust(dynamic_padding)

        # Format the log message
        message = record.getMessage()

        prefix = self.get_prefix(record.name)

        # Construct the final formatted log line
        return f"{timestamp} {level} {module_name} {prefix} | {message}"

    # this aint working quite right yet.
    def get_prefix(self, logger_name) -> str:
        if "auth" in logger_name:
            return self.EMOJI_PREFIXES["auth"]
        if "injector" in logger_name:
            return self.EMOJI_PREFIXES["injector"]
        if "schema" in logger_name:
            return self.EMOJI_PREFIXES["schema"]
        if "resource" in logger_name:
            return self.EMOJI_PREFIXES["resource"]
        if "trace" in logger_name:
            return self.EMOJI_PREFIXES["trace"]
        if "dynamic" in logger_name:
            return self.EMOJI_PREFIXES["dynamic"]
        if "discovery" in logger_name:
            return self.EMOJI_PREFIXES["discovery"]
        if "capability" in logger_name:
            return self.EMOJI_PREFIXES["capability"]
        if "cli" in logger_name:
            return self.EMOJI_PREFIXES["cli"]
        if "error" in logger_name:
            return self.EMOJI_PREFIXES["error"]
        if "network" in logger_name:
            return self.EMOJI_PREFIXES["network"]
        if "performance" in logger_name:
            return self.EMOJI_PREFIXES["performance"]
        if "server" in logger_name:
            return self.EMOJI_PREFIXES["server"]
        if "hub.components" in logger_name:
            return self.EMOJI_PREFIXES["hub.components"]
        if "utils.crypto" in logger_name:
            return self.EMOJI_PREFIXES["utils.crypto"]

        return self.EMOJI_PREFIXES["core"]
