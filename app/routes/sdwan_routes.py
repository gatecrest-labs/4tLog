from flask import Blueprint, jsonify, render_template, session

from app import registry
from app.config import Config
from app.decorators import tab_required
from app.groups import get_allowed_adoms
from app.sdwan_cache import get_cached

bp = Blueprint("sdwan", __name__)

registry.register("sdwan", "SD-WAN", "sdwan.index")


@bp.route("/sdwan")
@tab_required("sdwan")
def index():
    return render_template("sdwan.html", user=session["user"])


@bp.route("/api/sdwan")
@tab_required("sdwan")
def api_sdwan():
    ad_groups = session.get("ad_groups", [])
    allowed = get_allowed_adoms(session["user"], ad_groups=ad_groups, role=session.get("role"))
    snapshot = get_cached()
    targets = snapshot.get("targets", [])
    if allowed is not None:
        targets = [t for t in targets if t.get("label") in allowed]
    return jsonify(
        {
            "targets": targets,
            "collected_at": snapshot.get("collected_at"),
            "poll_interval": Config.SDWAN_POLL_INTERVAL,
        }
    )
