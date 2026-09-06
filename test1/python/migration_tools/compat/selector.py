class Selector:
    def __init__(self, environment):
        self.environment = environment

    def profile(self):
        # Runtime profile is external in the real system; represented here as a
        # deterministic mapping for static-analysis purposes.
        return "legacy" if self.environment == "partner-archive" else "modern"
