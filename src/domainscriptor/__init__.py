from importlib.metadata import metadata


def project_info(dist_name: str = "domainscriptor") -> dict:
    """Return name, version, description (Summary) from installed metadata."""
    m = metadata(dist_name)
    return {
        "name": m.get("Name"),
        "version": m.get("Version"),
        "banner": r"""
  ____                        _       ____            _       _
 |  _ \  ___  _ __ ___   __ _(_)_ __ / ___|  ___ _ __(_)_ __ | |_ ___  _ __
 | | | |/ _ \| '_ ` _ \ / _` | | '_ \\___ \ / __| '__| | '_ \| __/ _ \| '__|
 | |_| | (_) | | | | | | (_| | | | | |___) | (__| |  | | |_) | || (_) | |
 |____/ \___/|_| |_| |_|\__,_|_|_| |_|____/ \___|_|  |_| .__/ \__\___/|_|
                                                         |_|
 by Fabian Traxler
""",
        "description": (
            m.get("Summary") or ""
        ).strip(),  # maps to [project].description
    }
