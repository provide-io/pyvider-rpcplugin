# PyVider RPCPlugin - Development Guide

## Commands
- Test: `hatch run test:test`
- Run single test: `hatch run test:test tests/path/to/test.py::TestClass::test_method`
- Coverage: `hatch run test:coverage`
- Lint: `hatch run test:lint`
- Format: `hatch run test:format`
- Typecheck: `hatch run test:typecheck`
- Security check: `hatch run test:security`
- Build Go plugin: `hatch run build:go`
- Documentation: `hatch run docs:build` or `hatch run docs:serve`
- Run app: `hatch run default:run`

## Code Style Guide
- **Imports**: Standard lib → third-party → project, grouped by type with blank lines
- **Types**: Use type hints everywhere; Protocol for interfaces, Union (|), TypedDict, NotRequired
- **Naming**: CamelCase (classes), snake_case (functions/methods), UPPER_SNAKE_CASE (constants)
- **Error handling**: Use custom exceptions hierarchy from RPCPluginError with specific subclasses
- **Formatting**: 4-space indentation, 88 char line length, single quotes for strings
- **Classes**: Use attrs for class definitions, properties for computed attributes
- **Logging**: Structured logging with context and emoji prefixes for visual categorization