from enum import Enum


class Context(Enum):
    debug = ("***\U0001f41e***", "::: Debugging information", "---🐞---")
    audit = ("***\U0001f4dc***", "::: Compliance and audit logs", "---📜---")
    telemetry = ("***\U0001f4f1***", "::: Performance and monitoring logs", "---📱---")
    user_action = ("***\U0001f464***", "::: User-initiated actions", "---👤---")
    system_event = ("***\U0001f5a5 ***", "::: Automated system events", "---🖥---")
    config = ("***\U00002699 ***", "::: Configuration changes", "---⚙---")
    external = ("***\U0001f30d***", "::: External API/service interactions", "---🌍---")
    background = ("***\U000023f3***", "::: Background tasks", "---⏳---")
    cache = ("***\U0001f5c4***", "::: Caching operations", "---🗄---")
    automation = ("***\U0001f916***", "::: Automated process execution", "---🤖---")
    security = ("***\U0001f510***", "::: Security-related events", "---🔐---")
    maintenance = (
        "***\U0001f527***",
        "::: Scheduled maintenance operations",
        "---🔧---",
    )
    error_report = (
        "***\U0001f4dd***",
        "::: User or system-generated error reports",
        "---📝---",
    )
    incident = ("***\U0001f6a8***", "::: Incident response logs", "---🚨---")
    analytics = ("***\U0001f4ca***", "::: Data analytics and insights", "---📊---")


class Domain(Enum):
    server = ("***\U0001f3e0***", "::: Server-related logs", "---🏠---")
    client = ("***\U0001f64b***", "::: Client-side operations", "---🙋---")
    plugin = ("***\U0001f50c***", "::: Plugin behavior", "---🔌---")
    network = ("***\U0001f310***", "::: Network operations", "---🌐---")
    api = ("***\U0001f4f6***", "::: API interactions", "---📶---")
    task = ("***\U00002699***", "::: Task processing", "---⚙---")
    security = ("***\U0001f6a8***", "::: Security alerts", "---🚨---")
    database = ("***\U0001f5c4***", "::: Database queries", "---🗄---")
    file = ("***\U0001f4c2***", "::: File system actions", "---📂---")
    telemetry = ("***\U0001f6f0***", "::: Performance and monitoring logs", "---🛰---")
    message_queue = (
        "***\U0001f4ec***",
        "::: Message queue and broker activity",
        "---📬---",
    )
    hardware = ("***\U0001f4be***", "::: Hardware-related events", "---💾---")
    cloud = ("***\U00002601***", "::: Cloud-based operations", "---☁---")
    storage = ("***\U0001f4e6***", "::: Storage-related events", "---📦---")
    auth = ("***\U0001f511***", "::: Authentication and authorization", "---🔑---")
    logging = ("***\U0001f4dd***", "::: Logging subsystem events", "---📝---")
    middleware = ("***\U0001f9f0***", "::: Middleware event processing", "---🧰---")
    blockchain = (
        "***\U0001f5fa***",
        "::: Blockchain transactions and validation",
        "---🕚---",
    )
    machine_learning = (
        "***\U0001f9e0***",
        "Machine learning and AI processing",
        "---🧠---",
    )


import wcwidth

# Force uniform emoji width for better alignment
EMOJI_PADDING = 3  # Adjust this if needed based on terminal behavior


def visible_width(text) -> int:
    """Calculate the displayed width of a string considering emoji width."""
    return sum(
        wcwidth.wcwidth(char) if wcwidth.wcwidth(char) > 0 else 1 for char in text
    )


def pad_text(text, width):
    """Pad text with spaces to match the expected display width."""
    display_width = visible_width(text)
    extra_padding = width - display_width
    return text + " " * extra_padding


def fix_emoji_spacing(text) -> str:
    """Wrap emojis with spaces to ensure uniform width."""
    return f" {' ' * EMOJI_PADDING}{text}{' ' * EMOJI_PADDING} "


def generate_table() -> None:
    """Generate a formatted table with enforced emoji spacing."""
    headers = ["Category", "Key", "C", "Description", "E"]
    table = [headers]

    for enum_class in [Context, Domain]:
        for item in enum_class:
            # Apply manual emoji spacing to prevent alignment issues
            padded_c = fix_emoji_spacing(item.value[0])
            padded_e = fix_emoji_spacing(item.value[2])
            table.append(
                [enum_class.__name__, item.name, padded_c, item.value[1], padded_e]
            )

    # Calculate column widths based on displayed width
    column_widths = [
        max(visible_width(str(row[i])) for row in table) for i in range(len(headers))
    ]

    # Add padding for readability
    padding = 2
    column_widths = [w + padding for w in column_widths]

    formatted_table_lines = []
    for row in table:
        formatted_cells = [
            pad_text(str(row[i]), column_widths[i]) for i in range(len(row))
        ]
        formatted_table_lines.append(" | ".join(formatted_cells))

    formatted_table = "\n".join(formatted_table_lines)
    print(formatted_table)


if __name__ == "__main__":
    generate_table()
