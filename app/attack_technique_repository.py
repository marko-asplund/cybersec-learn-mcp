import json

from app.attack_technique_render import render_attack_technique


class AttackTechniqueRepository:
    ATTACK_FILE_PATH = "data/attack/techniques.json"

    def __init__(self):
        with open(self.ATTACK_FILE_PATH, "r") as file:
            content = file.read()
        self.data = json.loads(content)
        self.techniques = self.data["techniques"]
        self.source = self.data["source"]

    def get_technique_by_id(self, technique_id: str) -> str:
        technique = self.techniques[technique_id]
        return render_attack_technique(technique_id, technique, self.source)
