from typing import Any


def validate_object(arguments: dict[str, Any], schema: dict[str, Any]) -> tuple[bool, str]:
    if schema.get("type") != "object" or not isinstance(arguments, dict):
        return False, "Arguments must be an object."
    required = schema.get("required", [])
    if any(name not in arguments for name in required):
        return False, "A required argument is missing."
    properties = schema.get("properties", {})
    for name, value in arguments.items():
        definition = properties.get(name)
        if definition is None:
            if schema.get("additionalProperties") is False:
                return False, "Unknown argument was provided."
            continue
        expected_type = definition.get("type")
        if expected_type == "string" and not isinstance(value, str):
            return False, f"Argument {name} must be a string."
        if expected_type == "boolean" and not isinstance(value, bool):
            return False, f"Argument {name} must be a boolean."
        if expected_type == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
            return False, f"Argument {name} must be an integer."
        if expected_type == "number" and (not isinstance(value, int | float) or isinstance(value, bool)):
            return False, f"Argument {name} must be a number."
    return True, "Schema valid."
