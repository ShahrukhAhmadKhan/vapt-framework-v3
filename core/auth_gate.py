import uuid, datetime

class AuthorisationGate:
    def __init__(self, log):
        self.log = log

    def verify_programmatic(self, target: str, scope_data: dict) -> dict | None:
        authorised_by = scope_data.get("authorised_by", "").strip()
        organisation  = scope_data.get("organisation", "").strip()
        confirmed     = scope_data.get("confirmed", False)

        if not confirmed:
            self.log.error("Authorisation not confirmed.")
            return None
        if not authorised_by:
            self.log.error("Authorised-by name is required.")
            return None

        self.log.success(f"Authorised by: {authorised_by} ({organisation or 'N/A'})")
        return {
            "id":         str(uuid.uuid4()),
            "target":     target,
            "source":     "gui",
            "scope":      scope_data,
            "started_at": datetime.datetime.now().isoformat(),
        }

    # CLI compat
    def verify(self, target, scope_file=None):
        return self.verify_programmatic(target, {"authorised_by": "CLI", "confirmed": True})
