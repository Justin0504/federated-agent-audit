"""Original vector icons with role-specific anchors; no external assets."""
from pathlib import Path
import subprocess
ROOT = Path(__file__).resolve().parent
robot = '<rect x="5" y="11" width="38" height="32" rx="9" fill="#C9DDEB"/><path d="M24 11V5"/><circle cx="24" cy="5" r="2" fill="#C79352"/><rect x="11" y="20" width="26" height="13" rx="5" fill="#304656"/><circle cx="18" cy="26" r="2" fill="white" stroke="none"/><circle cx="30" cy="26" r="2" fill="white" stroke="none"/><path d="M13 46h20"/>'
art = {
 'schedule_agent': robot + '<rect x="29" y="33" width="31" height="25" rx="4" fill="#FFF8ED"/><path d="M29 41h31M37 30v7M52 30v7"/><rect x="36" y="46" width="6" height="6" rx="1" fill="#C79352" stroke="none"/><path d="M47 48h6"/>',
 'location_agent': robot + '<path d="M45 60C40 54 30 45 30 37a15 15 0 0 1 30 0c0 8-10 17-15 23Z" fill="#F0D2C5"/><circle cx="45" cy="37" r="5" fill="#FFF"/>',
 'label_report': '<path d="M10 5h29l13 13v41H10Z" fill="#F4F7FA"/><path d="M39 5v13h13" fill="#C9DDEB"/><rect x="17" y="24" width="28" height="8" rx="3" fill="#DCE7F5"/><path d="M17 39h14M17 46h10"/><rect x="31" y="36" width="28" height="23" rx="5" fill="#E5ECE2"/><path d="M41 41l-2 13M49 41l-2 13M36 45h17M35 50h17"/>',
 'audit_graph': '<path d="M12 15l28-6 12 28-24 17-16-39M12 15l40 22M40 9L28 54" stroke="#8498A8"/><circle cx="12" cy="15" r="7" fill="#D2E0EE"/><circle cx="40" cy="9" r="6" fill="#EED8B8"/><circle cx="28" cy="54" r="6" fill="#E2E9D9"/><circle cx="52" cy="37" r="6" fill="#EAD2CB"/><circle cx="30" cy="30" r="13" fill="#FFF"/><path d="M39 40l14 16" stroke-width="6"/><path d="M24 30l4 4 8-9" stroke="#477969" stroke-width="3.5"/>',
 'versioned_action': '<rect x="6" y="6" width="40" height="37" rx="5" fill="#D5E5EF"/><path d="M14 16h24M14 23h17M14 30h11"/><rect x="26" y="32" width="33" height="26" rx="5" fill="#FFF7E8"/><circle cx="34" cy="40" r="2" fill="#C79352"/><circle cx="50" cy="50" r="2" fill="#C79352"/><path d="M34 42v7h12M39 40h10l-3-3M49 40l-3 3"/>',
 'release_check': '<rect x="6" y="5" width="34" height="45" rx="4" fill="#F3F6F8"/><path d="M13 16l3 3 5-6M13 29l3 3 5-6M26 16h7M26 29h7M13 41h17"/><path d="M44 25l16 6v12c0 9-8 16-16 19-8-3-16-10-16-19V31Z" fill="#DDE8DA"/><path d="M36 42l6 6 10-13" stroke="#477969" stroke-width="4"/>',
}
for name, body in art.items():
    svg = '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><g fill="none" stroke="#304656" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">' + body + '</g></svg>'
    (ROOT / f'{name}.svg').write_text(svg)
    subprocess.run(['rsvg-convert','-f','pdf',str(ROOT/f'{name}.svg'),'-o',str(ROOT/f'{name}.pdf')], check=True)
