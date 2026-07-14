def __getattr__(name):
    raise RuntimeError(
        f"Garaga native helper {name} is disabled; use the pinned pure-Python hint builder"
    )
