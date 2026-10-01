from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HoneyAsset:
    asset_id: str
    kind: str
    marker: str


class HoneyAssetRegistry:
    def __init__(self, assets: tuple[HoneyAsset, ...] = ()) -> None:
        self._assets = assets

    def scan(self, tool_name: str, arguments: dict[str, Any]) -> HoneyAsset | None:
        values = [tool_name, *self._strings(arguments)]
        for asset in self._assets:
            if any(asset.marker in value for value in values):
                return asset
        return None

    @staticmethod
    def _strings(value: Any) -> list[str]:
        if isinstance(value, dict):
            return [item for child in value.values() for item in HoneyAssetRegistry._strings(child)]
        if isinstance(value, list):
            return [item for child in value for item in HoneyAssetRegistry._strings(child)]
        return [value] if isinstance(value, str) else []
