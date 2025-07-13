from flask import Blueprint, request, jsonify
from src.hybrid_waf.utils.exporter import export_to_csv, export_to_json

main_bp = Blueprint('main', __name__)

# Dummy IOCs (Replace with real data source)
ioc_store = [
    {"ip": "192.168.1.1", "attack_type": "SQLi", "timestamp": "2025-07-01 16:00"},
    {"ip": "192.168.1.2", "attack_type": "XSS", "timestamp": "2025-07-01 16:05"},
]

@main_bp.route('/export', methods=['GET'])
def export_data():
    fmt = request.args.get('format', 'json')
    if not ioc_store:
        return jsonify({"message": "No IOCs to export"}), 404

    try:
        if fmt == 'csv':
            export_to_csv(ioc_store)
        else:
            export_to_json(ioc_store)
        return jsonify({"message": f"IOCs exported as {fmt.upper()}"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
