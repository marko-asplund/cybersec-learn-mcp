import json
from typing import Any

from app.attack_technique_render import render_attack_technique
from app.errors import ResourceNotFound


class AttackTechniqueRepository:
    ATTACK_FILE_PATH = "data/attack/techniques.json"

    def __init__(self) -> None:
        with open(self.ATTACK_FILE_PATH, "r") as file:
            content = file.read()
        self.data: dict[str, Any] = json.loads(content)
        self.techniques: dict[str, dict[str, Any]] = self.data["techniques"]
        self.source: dict[str, Any] = self.data["source"]

    def get_technique_by_id(self, technique_id: str) -> str:
        technique = self.techniques.get(technique_id)
        if technique is None:
            raise ResourceNotFound(f"Unknown ATT&CK technique: {technique_id}")
        return render_attack_technique(technique_id, technique, self.source)
