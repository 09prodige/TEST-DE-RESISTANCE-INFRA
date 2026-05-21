import json
from datetime import datetime, timezone


class Report:
    def __init__(self, results: dict):
        self.results = results
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        return json.dumps({
            "generated_at": self.generated_at,
            "results": self.results
        }, indent=2)

    def save(self, filename: str, fmt: str = "json"):
        if fmt == "json":
            path = f"{filename}.json"
            with open(path, "w") as f:
                f.write(self.to_json())
        elif fmt == "html":
            # TODO: implement HTML report with Jinja2
            raise NotImplementedError("HTML report — sprint 4")
        elif fmt == "pdf":
            # TODO: implement PDF report
            raise NotImplementedError("PDF report — sprint 4")


if __name__ == "__main__":
    r = Report({"target": "example.com", "modules": {}})
    print(r.to_json())
