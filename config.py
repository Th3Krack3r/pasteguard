# PasteGuard configuration.
#
# AD_SLOT_HTML: the ad slot rendered in the page layout. To monetize, paste
# your ad network's code inside the div (replacing the placeholder comment).
# Keep the outer <div class="ad-slot"> wrapper so the layout stays intact.
AD_SLOT_HTML = """<div class="ad-slot">
<!-- PASTE AD NETWORK CODE HERE -->
<span class="ad-label">Advertisement</span>
</div>"""

# STRIPE_PRO_LINK: checkout link for PasteGuard Pro ($5 one-time).
# Replace this placeholder with the real Stripe payment link before
# advertising Pro. The upsell button on the page points at this constant.
STRIPE_PRO_LINK = "https://buy.stripe.com/4gM6oIfj387L1di04jfEk05"

# Server defaults (overridable with: python3 app.py [port] or PORT env var).
HOST = "127.0.0.1"
PORT = 8000

# Safety cap on a single paste, in characters.
MAX_INPUT_CHARS = 200_000
