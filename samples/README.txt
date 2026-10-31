Demo emails for Sentinel-Graph (synthetic and safe).

Every link uses the reserved .invalid domain, which can never resolve, so the sandbox
fails fast and never contacts a real site. Drop these on http://localhost:5173.

01_phishing_apple_lure.eml   The defense demo lure (identical to the test suite's): SPF/DMARC
                             fail, Apple display-name spoof, a private hop between public
                             relays, a backwards clock. Expected risk with the deployed
                             12-feature model: 61/100.
02_benign_meeting_minutes.eml The benign counterpart (auth passes, one hop, no link).
                             Expected risk: 39/100.
03_coercive_multi_hop.eml    Built to show the newer panels: three public relay hops (arcs on
                             the globe), four coercive phrases (NLP meter full), and a link
                             whose domain label "xkqjfhzyw" is random-looking (DGA 3.17 bits,
                             outside the legitimate band). Expected risk: 90/100.

The verdict badge (e.g. CRITICAL) comes from the stand-in language model, which always says
CRITICAL. Read the risk number and the evidence panels instead.
