#!/usr/bin/env python3
"""
tranco_sector_sample.py

Generates a stratified sample of 50 HTTPS endpoints per sector from the
Tranco top-1M list (list ID: VQ3PN, dated 2026-01-01).

Methodology (three-tier classification):
  Tier 1 — Explicit domain dictionary: manually curated, highest confidence.
  Tier 2 — TLD pattern rules: .gov/.mil → Government, .edu → Education.
  Tier 3 — Keyword heuristics: domain-name substring patterns per sector.

Within each sector the top 50 domains by Tranco rank are selected.
A domain is assigned to exactly one sector (first match wins in rank order).

Output: tranco_vq3pn_sector_sample.json
  Includes full audit trail: Tranco rank, domain, sector, classification tier,
  classification basis, and metadata identifying the source list.

Reproducibility:
  Tranco list VQ3PN is permanently archived at:
    https://tranco-list.eu/list/VQ3PN/full
  Re-running this script against that list reproduces the sample exactly.

Citation:
  Le Pochat, V. et al. (2019). Tranco: A Research-Oriented Top Sites Ranking
  Hardened Against Manipulation. NDSS 2019. DOI: 10.14722/ndss.2019.23386
"""

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TRANCO_LIST_ID = "VQ3PN"
TRANCO_DATE = "2026-01-01"
TRANCO_URL = f"https://tranco-list.eu/download/{TRANCO_LIST_ID}/200000"
TOP_N_DOWNLOAD = 200_000
SAMPLES_PER_SECTOR = 50

SECTORS = [
    "Finance",
    "Government",
    "Healthcare",
    "Education",
    "Technology",
    "Telecommunications",
    "Media/News",
    "Retail/Ecommerce",
    "Travel/Hospitality",
    "Transportation",
    "Energy/Utilities",
    "Manufacturing",
    "Real Estate",
    "Agriculture/Food",
    "Legal",
    "Professional Services",
    "Nonprofit",
    "Sports",
    "Gaming",
    "Social Media",
    "Science/Research",
]

REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_PATH = REPO_ROOT / "papers" / "paper02" / "tranco_vq3pn_sector_sample.json"

# ---------------------------------------------------------------------------
# Tier 1 — Explicit domain → sector mapping
# Rationale: well-known organisations whose primary sector is unambiguous.
# Sorted alphabetically within each sector for maintainability.
# ---------------------------------------------------------------------------
DOMAIN_MAP: dict[str, str] = {
    # ------------------------------------------------------------------
    # Finance
    # ------------------------------------------------------------------
    "1inch.io": "Finance",
    "ally.com": "Finance",
    "americanexpress.com": "Finance",
    "ameriprise.com": "Finance",
    "axa.com": "Finance",
    "bankofamerica.com": "Finance",
    "bankofchina.com": "Finance",
    "barclays.com": "Finance",
    "binance.com": "Finance",
    "blackrock.com": "Finance",
    "bloomberg.com": "Finance",
    "bnpparibas.com": "Finance",
    "brex.com": "Finance",
    "capitalone.com": "Finance",
    "chase.com": "Finance",
    "cibc.com": "Finance",
    "citi.com": "Finance",
    "citigroup.com": "Finance",
    "coinbase.com": "Finance",
    "commbank.com.au": "Finance",
    "credit-agricole.com": "Finance",
    "creditsuisse.com": "Finance",
    "cryptocom.com": "Finance",
    "db.com": "Finance",
    "deutsche-bank.de": "Finance",
    "deutschebank.com": "Finance",
    "discover.com": "Finance",
    "dwolla.com": "Finance",
    "etrade.com": "Finance",
    "fidelity.com": "Finance",
    "ft.com": "Finance",
    "fundingcircle.com": "Finance",
    "goldmansachs.com": "Finance",
    "hsbc.com": "Finance",
    "icicibank.com": "Finance",
    "ing.com": "Finance",
    "intuit.com": "Finance",
    "investopedia.com": "Finance",
    "jpmorgan.com": "Finance",
    "jpmorganchase.com": "Finance",
    "klarna.com": "Finance",
    "kraken.com": "Finance",
    "lloydsbank.com": "Finance",
    "lufax.com": "Finance",
    "marketwatch.com": "Finance",
    "mastercard.com": "Finance",
    "metlife.com": "Finance",
    "monzo.com": "Finance",
    "morganstanley.com": "Finance",
    "n26.com": "Finance",
    "nasdaq.com": "Finance",
    "natwest.com": "Finance",
    "nyse.com": "Finance",
    "nymex.com": "Finance",
    "payoneer.com": "Finance",
    "paypal.com": "Finance",
    "plaid.com": "Finance",
    "pnc.com": "Finance",
    "prudential.com": "Finance",
    "qonto.com": "Finance",
    "rbc.com": "Finance",
    "regions.com": "Finance",
    "revolut.com": "Finance",
    "robinhood.com": "Finance",
    "santander.com": "Finance",
    "sberbank.ru": "Finance",
    "schwab.com": "Finance",
    "scotiabank.com": "Finance",
    "sofi.com": "Finance",
    "square.com": "Finance",
    "standardchartered.com": "Finance",
    "stripe.com": "Finance",
    "svb.com": "Finance",
    "synchrony.com": "Finance",
    "tdbank.com": "Finance",
    "td.com": "Finance",
    "tinkoff.ru": "Finance",
    "tradingview.com": "Finance",
    "transferwise.com": "Finance",
    "truist.com": "Finance",
    "ubs.com": "Finance",
    "usbank.com": "Finance",
    "vanguard.com": "Finance",
    "venmo.com": "Finance",
    "visa.com": "Finance",
    "wellsfargo.com": "Finance",
    "wise.com": "Finance",
    "wsj.com": "Finance",
    "xe.com": "Finance",
    "zelle.com": "Finance",
    "zerodha.com": "Finance",
    # ------------------------------------------------------------------
    # Government  (TLD-rules catch most .gov/.mil — dictionary for non-.gov)
    # ------------------------------------------------------------------
    "bundesregierung.de": "Government",
    "canada.ca": "Government",
    "ec.europa.eu": "Government",
    "elysee.fr": "Government",
    "europa.eu": "Government",
    "gc.ca": "Government",
    "gov.au": "Government",
    "gov.br": "Government",
    "gov.cn": "Government",
    "gov.in": "Government",
    "gov.sg": "Government",
    "gov.uk": "Government",
    "government.ru": "Government",
    "gouvernement.fr": "Government",
    "india.gov.in": "Government",
    "kremlin.ru": "Government",
    "mfa.gov.cn": "Government",
    "mod.uk": "Government",
    "parliament.uk": "Government",
    "pmo.gov.in": "Government",
    "president.gov.ua": "Government",
    "president.ru": "Government",
    "premier.gov.cn": "Government",
    "premier.ru": "Government",
    "riksdagen.se": "Government",
    "senado.leg.br": "Government",
    "service.gov.uk": "Government",
    "un.org": "Government",
    "www.gov.br": "Government",
    "www.gov.uk": "Government",
    # ------------------------------------------------------------------
    # Healthcare
    # ------------------------------------------------------------------
    "abbott.com": "Healthcare",
    "abbvie.com": "Healthcare",
    "amedisys.com": "Healthcare",
    "astrazeneca.com": "Healthcare",
    "bayer.com": "Healthcare",
    "beckmanncoulter.com": "Healthcare",
    "biogen.com": "Healthcare",
    "biotechne.com": "Healthcare",
    "bostonscientific.com": "Healthcare",
    "brightspringhealth.com": "Healthcare",
    "bsci.com": "Healthcare",
    "cardinal.com": "Healthcare",
    "cigna.com": "Healthcare",
    "commonwealthfund.org": "Healthcare",
    "cvs.com": "Healthcare",
    "cvshealth.com": "Healthcare",
    "daiichisankyo.com": "Healthcare",
    "doctorsondemand.com": "Healthcare",
    "elevahealth.com": "Healthcare",
    "elevancehealth.com": "Healthcare",
    "fresenius.com": "Healthcare",
    "gsk.com": "Healthcare",
    "healthgrades.com": "Healthcare",
    "healthline.com": "Healthcare",
    "hhs.gov": "Healthcare",
    "humana.com": "Healthcare",
    "icahn.mssm.edu": "Healthcare",
    "jnj.com": "Healthcare",
    "johnsonhealthtech.com": "Healthcare",
    "kaiserpermanente.org": "Healthcare",
    "kp.org": "Healthcare",
    "labcorp.com": "Healthcare",
    "lilly.com": "Healthcare",
    "mayoclinic.org": "Healthcare",
    "mdsol.com": "Healthcare",
    "medscape.com": "Healthcare",
    "medtronic.com": "Healthcare",
    "merck.com": "Healthcare",
    "mgh.harvard.edu": "Healthcare",
    "nhs.uk": "Healthcare",
    "novartis.com": "Healthcare",
    "novanthealth.org": "Healthcare",
    "optum.com": "Healthcare",
    "pfizer.com": "Healthcare",
    "philips.com": "Healthcare",
    "questdiagnostics.com": "Healthcare",
    "roche.com": "Healthcare",
    "sanofigenzyme.com": "Healthcare",
    "sanofi.com": "Healthcare",
    "sharecare.com": "Healthcare",
    "siemens-healthineers.com": "Healthcare",
    "stryker.com": "Healthcare",
    "teladoc.com": "Healthcare",
    "teva.com": "Healthcare",
    "thermofisher.com": "Healthcare",
    "uhc.com": "Healthcare",
    "unitedhealth.com": "Healthcare",
    "unitedhealthgroup.com": "Healthcare",
    "walgreens.com": "Healthcare",
    "webmd.com": "Healthcare",
    "who.int": "Healthcare",
    "zimmer.com": "Healthcare",
    "zocdoc.com": "Healthcare",
    # ------------------------------------------------------------------
    # Education  (TLD-rules catch .edu — dictionary for non-.edu)
    # ------------------------------------------------------------------
    "brilliantearth.com": "Education",     # not this — remove below
    "cambridge.org": "Education",
    "chegg.com": "Education",
    "classlink.com": "Education",
    "clevelandclinic.org": "Education",    # actually healthcare, overridden
    "codecademy.com": "Education",
    "collegeboard.org": "Education",
    "coursera.org": "Education",
    "duolingo.com": "Education",
    "edx.org": "Education",
    "fulbrightprogram.org": "Education",
    "futurelearn.com": "Education",
    "khanacademy.org": "Education",
    "learnpython.org": "Education",
    "lynda.com": "Education",
    "masterclass.com": "Education",
    "moodle.org": "Education",
    "ocw.mit.edu": "Education",
    "openuniversity.edu": "Education",
    "oxford.ac.uk": "Education",
    "pearson.com": "Education",
    "pluralsight.com": "Education",
    "quizlet.com": "Education",
    "rosettastone.com": "Education",
    "schoology.com": "Education",
    "skillshare.com": "Education",
    "udacity.com": "Education",
    "udemy.com": "Education",
    "wikipedia.org": "Education",          # broad-education / also nonprofit; assigned here
    # Note: .edu TLDs handled by Tier 2 (covers mit.edu, harvard.edu, etc.)
    # ------------------------------------------------------------------
    # Technology
    # ------------------------------------------------------------------
    "adobe.com": "Technology",
    "airflow.apache.org": "Technology",
    "amd.com": "Technology",
    "android.com": "Technology",
    "ansible.com": "Technology",
    "apache.org": "Technology",
    "atlassian.com": "Technology",
    "autodesk.com": "Technology",
    "aws.amazon.com": "Technology",
    "azure.com": "Technology",
    "cloudflare.com": "Technology",
    "cursor.sh": "Technology",
    "databricks.com": "Technology",
    "debian.org": "Technology",
    "dell.com": "Technology",
    "digitalocean.com": "Technology",
    "docker.com": "Technology",
    "dropbox.com": "Technology",
    "elastic.co": "Technology",
    "figma.com": "Technology",
    "github.com": "Technology",
    "gitlab.com": "Technology",
    "golang.org": "Technology",
    "google.com": "Technology",
    "hashicorp.com": "Technology",
    "hp.com": "Technology",
    "huawei.com": "Technology",
    "ibm.com": "Technology",
    "intel.com": "Technology",
    "jetbrains.com": "Technology",
    "jquery.com": "Technology",
    "kubernetes.io": "Technology",
    "lenovo.com": "Technology",
    "linux.org": "Technology",
    "meta.com": "Technology",
    "microsoft.com": "Technology",
    "mozilla.org": "Technology",
    "mysql.com": "Technology",
    "netflix.com": "Technology",
    "nginx.org": "Technology",
    "nodejs.org": "Technology",
    "notion.so": "Technology",
    "nvidia.com": "Technology",
    "openai.com": "Technology",
    "oracle.com": "Technology",
    "php.net": "Technology",
    "python.org": "Technology",
    "qualcomm.com": "Technology",
    "redhat.com": "Technology",
    "rust-lang.org": "Technology",
    "salesforce.com": "Technology",
    "samsung.com": "Technology",
    "sap.com": "Technology",
    "servicenow.com": "Technology",
    "slack.com": "Technology",
    "snowflake.com": "Technology",
    "sony.com": "Technology",
    "sourceforge.net": "Technology",
    "stackoverflow.com": "Technology",
    "tableau.com": "Technology",
    "terraform.io": "Technology",
    "toshiba.com": "Technology",
    "typescript.org": "Technology",
    "ubuntu.com": "Technology",
    "vmware.com": "Technology",
    "w3.org": "Technology",
    "w3schools.com": "Technology",
    "workday.com": "Technology",
    "xiaomi.com": "Technology",
    "zendesk.com": "Technology",
    "zoom.us": "Technology",
    # ------------------------------------------------------------------
    # Telecommunications
    # ------------------------------------------------------------------
    "1und1.de": "Telecommunications",
    "airtel.in": "Telecommunications",
    "att.com": "Telecommunications",
    "att.net": "Telecommunications",
    "bell.ca": "Telecommunications",
    "bouyguestelecom.fr": "Telecommunications",
    "bt.com": "Telecommunications",
    "chinatelecom.com.cn": "Telecommunications",
    "chinatelecom.cn": "Telecommunications",
    "comcast.com": "Telecommunications",
    "comcast.net": "Telecommunications",
    "cox.com": "Telecommunications",
    "dtac.co.th": "Telecommunications",
    "etisalat.ae": "Telecommunications",
    "fastweb.it": "Telecommunications",
    "free.fr": "Telecommunications",
    "frontier.com": "Telecommunications",
    "jio.com": "Telecommunications",
    "kddi.com": "Telecommunications",
    "lge.com": "Telecommunications",
    "megafon.ru": "Telecommunications",
    "mtn.com": "Telecommunications",
    "mts.ru": "Telecommunications",
    "ntt.com": "Telecommunications",
    "nttdocomo.com": "Telecommunications",
    "orange.com": "Telecommunications",
    "rogerscommunications.com": "Telecommunications",
    "rogers.com": "Telecommunications",
    "softbank.jp": "Telecommunications",
    "spectrum.com": "Telecommunications",
    "sprint.com": "Telecommunications",
    "t-mobile.com": "Telecommunications",
    "t-online.de": "Telecommunications",
    "telecom.com": "Telecommunications",
    "telekomunikasi.co.id": "Telecommunications",
    "telekom.com": "Telecommunications",
    "telekom.de": "Telecommunications",
    "telenet.be": "Telecommunications",
    "telefonica.com": "Telecommunications",
    "telstra.com.au": "Telecommunications",
    "telus.com": "Telecommunications",
    "threeuk.com": "Telecommunications",
    "tmobile.com": "Telecommunications",
    "twilio.com": "Telecommunications",
    "verizon.com": "Telecommunications",
    "verizon.net": "Telecommunications",
    "viber.com": "Telecommunications",
    "vodafone.com": "Telecommunications",
    "vodafone.co.uk": "Telecommunications",
    "windstream.com": "Telecommunications",
    "xfinity.com": "Telecommunications",
    # ------------------------------------------------------------------
    # Media/News
    # ------------------------------------------------------------------
    "abcnews.go.com": "Media/News",
    "apnews.com": "Media/News",
    "axios.com": "Media/News",
    "bbc.co.uk": "Media/News",
    "bbc.com": "Media/News",
    "bild.de": "Media/News",
    "bloomberg.co.jp": "Media/News",
    "businessinsider.com": "Media/News",
    "buzzfeed.com": "Media/News",
    "cbsnews.com": "Media/News",
    "cnbc.com": "Media/News",
    "cnn.com": "Media/News",
    "corriere.it": "Media/News",
    "dailymail.co.uk": "Media/News",
    "dailymotion.com": "Media/News",
    "elpais.com": "Media/News",
    "focus.de": "Media/News",
    "forbes.com": "Media/News",
    "foxnews.com": "Media/News",
    "huffpost.com": "Media/News",
    "independent.co.uk": "Media/News",
    "indiatimes.com": "Media/News",
    "latimes.com": "Media/News",
    "lefigaro.fr": "Media/News",
    "lemonde.fr": "Media/News",
    "leparisien.fr": "Media/News",
    "mirror.co.uk": "Media/News",
    "msn.com": "Media/News",
    "nbcnews.com": "Media/News",
    "newsweek.com": "Media/News",
    "nikkei.com": "Media/News",
    "npr.org": "Media/News",
    "nypost.com": "Media/News",
    "nytimes.com": "Media/News",
    "pbs.org": "Media/News",
    "repubblica.it": "Media/News",
    "reuters.com": "Media/News",
    "rt.com": "Media/News",
    "spiegel.de": "Media/News",
    "substack.com": "Media/News",
    "ted.com": "Media/News",
    "telegraph.co.uk": "Media/News",
    "theguardian.com": "Media/News",
    "theatlantic.com": "Media/News",
    "time.com": "Media/News",
    "usatoday.com": "Media/News",
    "vice.com": "Media/News",
    "washingtonpost.com": "Media/News",
    "welt.de": "Media/News",
    "wired.com": "Media/News",
    # Note: wsj.com also in Finance — wsj.com → Finance via _OVERRIDES below
    # ------------------------------------------------------------------
    # Retail/Ecommerce
    # ------------------------------------------------------------------
    "aliexpress.com": "Retail/Ecommerce",
    "allegro.pl": "Retail/Ecommerce",
    "amazon.ca": "Retail/Ecommerce",
    "amazon.co.jp": "Retail/Ecommerce",
    "amazon.co.uk": "Retail/Ecommerce",
    "amazon.com": "Retail/Ecommerce",
    "amazon.com.au": "Retail/Ecommerce",
    "amazon.com.br": "Retail/Ecommerce",
    "amazon.de": "Retail/Ecommerce",
    "amazon.es": "Retail/Ecommerce",
    "amazon.fr": "Retail/Ecommerce",
    "amazon.in": "Retail/Ecommerce",
    "amazon.it": "Retail/Ecommerce",
    "bestbuy.com": "Retail/Ecommerce",
    "bol.com": "Retail/Ecommerce",
    "carrefour.com": "Retail/Ecommerce",
    "costco.com": "Retail/Ecommerce",
    "ebay.co.uk": "Retail/Ecommerce",
    "ebay.com": "Retail/Ecommerce",
    "ebay.de": "Retail/Ecommerce",
    "etsy.com": "Retail/Ecommerce",
    "flipkart.com": "Retail/Ecommerce",
    "fnac.com": "Retail/Ecommerce",
    "gap.com": "Retail/Ecommerce",
    "groupon.com": "Retail/Ecommerce",
    "hm.com": "Retail/Ecommerce",
    "homedepot.com": "Retail/Ecommerce",
    "ikea.com": "Retail/Ecommerce",
    "kohls.com": "Retail/Ecommerce",
    "lazada.com": "Retail/Ecommerce",
    "lowes.com": "Retail/Ecommerce",
    "macys.com": "Retail/Ecommerce",
    "mercadolibre.com": "Retail/Ecommerce",
    "mercadolibre.com.ar": "Retail/Ecommerce",
    "mercadolivre.com.br": "Retail/Ecommerce",
    "myshopify.com": "Retail/Ecommerce",
    "myntra.com": "Retail/Ecommerce",
    "newegg.com": "Retail/Ecommerce",
    "next.co.uk": "Retail/Ecommerce",
    "nike.com": "Retail/Ecommerce",
    "nordstrom.com": "Retail/Ecommerce",
    "otto.de": "Retail/Ecommerce",
    "overstock.com": "Retail/Ecommerce",
    "rakuten.co.jp": "Retail/Ecommerce",
    "rakuten.com": "Retail/Ecommerce",
    "samsung.com/shop": "Retail/Ecommerce",
    "shein.com": "Retail/Ecommerce",
    "shopee.co.id": "Retail/Ecommerce",
    "shopee.com.br": "Retail/Ecommerce",
    "shopify.com": "Retail/Ecommerce",
    "target.com": "Retail/Ecommerce",
    "temu.com": "Retail/Ecommerce",
    "tesco.com": "Retail/Ecommerce",
    "walmart.com": "Retail/Ecommerce",
    "wildberries.ru": "Retail/Ecommerce",
    "zalando.com": "Retail/Ecommerce",
    "zara.com": "Retail/Ecommerce",
    # ------------------------------------------------------------------
    # Travel/Hospitality
    # ------------------------------------------------------------------
    "agoda.com": "Travel/Hospitality",
    "airbnb.com": "Travel/Hospitality",
    "american.com": "Travel/Hospitality",
    "americanairlines.com": "Travel/Hospitality",
    "ba.com": "Travel/Hospitality",
    "booking.com": "Travel/Hospitality",
    "britishairways.com": "Travel/Hospitality",
    "carnival.com": "Travel/Hospitality",
    "delta.com": "Travel/Hospitality",
    "emirates.com": "Travel/Hospitality",
    "expedia.com": "Travel/Hospitality",
    "flysas.com": "Travel/Hospitality",
    "four-seasons.com": "Travel/Hospitality",
    "fourseasons.com": "Travel/Hospitality",
    "hilton.com": "Travel/Hospitality",
    "hotels.com": "Travel/Hospitality",
    "hyatt.com": "Travel/Hospitality",
    "ihg.com": "Travel/Hospitality",
    "intercontinental.com": "Travel/Hospitality",
    "kayak.com": "Travel/Hospitality",
    "klm.com": "Travel/Hospitality",
    "lufthansa.com": "Travel/Hospitality",
    "mariott.com": "Travel/Hospitality",
    "marriott.com": "Travel/Hospitality",
    "momondo.com": "Travel/Hospitality",
    "norwegian.com": "Travel/Hospitality",
    "orbitz.com": "Travel/Hospitality",
    "priceline.com": "Travel/Hospitality",
    "qatarairways.com": "Travel/Hospitality",
    "radissonhotels.com": "Travel/Hospitality",
    "ryanair.com": "Travel/Hospitality",
    "singaporeair.com": "Travel/Hospitality",
    "skyscanner.com": "Travel/Hospitality",
    "southwest.com": "Travel/Hospitality",
    "tripadvisor.com": "Travel/Hospitality",
    "trivago.com": "Travel/Hospitality",
    "united.com": "Travel/Hospitality",
    "vrbo.com": "Travel/Hospitality",
    "westin.com": "Travel/Hospitality",
    "wyndhamhotels.com": "Travel/Hospitality",
    # ------------------------------------------------------------------
    # Transportation  (logistics, shipping, rail, road freight)
    # ------------------------------------------------------------------
    "amtrak.com": "Transportation",
    "bnsf.com": "Transportation",
    "cargotec.com": "Transportation",
    "ceva.com": "Transportation",
    "cn.ca": "Transportation",
    "csx.com": "Transportation",
    "dbschenker.com": "Transportation",
    "dhl.com": "Transportation",
    "dpd.com": "Transportation",
    "dsv.com": "Transportation",
    "dpdgroup.com": "Transportation",
    "fedex.com": "Transportation",
    "freightos.com": "Transportation",
    "geodis.com": "Transportation",
    "gls-group.eu": "Transportation",
    "hapag-lloyd.com": "Transportation",
    "hermes.de": "Transportation",
    "jbhunt.com": "Transportation",
    "kuehne-nagel.com": "Transportation",
    "maersk.com": "Transportation",
    "msc.com": "Transportation",
    "nordhavn.com": "Transportation",
    "panalpina.com": "Transportation",
    "postnl.nl": "Transportation",
    "postaitaliana.it": "Transportation",
    "royalmail.com": "Transportation",
    "sendle.com": "Transportation",
    "sncf.com": "Transportation",
    "tnt.com": "Transportation",
    "toll.com": "Transportation",
    "ups.com": "Transportation",
    "usps.com": "Transportation",
    "xpo.com": "Transportation",
    "yrc.com": "Transportation",
    "yanwen.com": "Transportation",
    # ------------------------------------------------------------------
    # Energy/Utilities
    # ------------------------------------------------------------------
    "aep.com": "Energy/Utilities",
    "alliantenergy.com": "Energy/Utilities",
    "ameren.com": "Energy/Utilities",
    "avangrid.com": "Energy/Utilities",
    "bp.com": "Energy/Utilities",
    "centrica.com": "Energy/Utilities",
    "cez.cz": "Energy/Utilities",
    "chevron.com": "Energy/Utilities",
    "cnooc.com.cn": "Energy/Utilities",
    "conedison.com": "Energy/Utilities",
    "conocophillips.com": "Energy/Utilities",
    "dominionenergy.com": "Energy/Utilities",
    "drax.com": "Energy/Utilities",
    "dte.com": "Energy/Utilities",
    "duke-energy.com": "Energy/Utilities",
    "dukeenergy.com": "Energy/Utilities",
    "e.on.com": "Energy/Utilities",
    "edf.fr": "Energy/Utilities",
    "edp.com": "Energy/Utilities",
    "enelamerica.com": "Energy/Utilities",
    "enel.com": "Energy/Utilities",
    "engie.com": "Energy/Utilities",
    "eni.com": "Energy/Utilities",
    "entergy.com": "Energy/Utilities",
    "equinor.com": "Energy/Utilities",
    "exeloncorp.com": "Energy/Utilities",
    "exelon.com": "Energy/Utilities",
    "exxonmobil.com": "Energy/Utilities",
    "firstenergy.com": "Energy/Utilities",
    "fortisbc.com": "Energy/Utilities",
    "gazprom.com": "Energy/Utilities",
    "halliburton.com": "Energy/Utilities",
    "iberdrola.com": "Energy/Utilities",
    "nationalgrid.com": "Energy/Utilities",
    "nexteraenergy.com": "Energy/Utilities",
    "nrg.com": "Energy/Utilities",
    "nrgenergy.com": "Energy/Utilities",
    "oge.com": "Energy/Utilities",
    "pge.com": "Energy/Utilities",
    "pgecorp.com": "Energy/Utilities",
    "pinnaclewest.com": "Energy/Utilities",
    "pseg.com": "Energy/Utilities",
    "rosneft.com": "Energy/Utilities",
    "rwe.com": "Energy/Utilities",
    "saudi-aramco.com": "Energy/Utilities",
    "saudiaramco.com": "Energy/Utilities",
    "schlumberger.com": "Energy/Utilities",
    "scottishpower.com": "Energy/Utilities",
    "sempra.com": "Energy/Utilities",
    "shell.com": "Energy/Utilities",
    "siemensenergy.com": "Energy/Utilities",
    "southernco.com": "Energy/Utilities",
    "statoil.com": "Energy/Utilities",
    "sunpower.com": "Energy/Utilities",
    "tesla.com": "Energy/Utilities",
    "totalenergies.com": "Energy/Utilities",
    "vattenfall.com": "Energy/Utilities",
    "vestas.com": "Energy/Utilities",
    "wecenergygroup.com": "Energy/Utilities",
    "woodmackenzie.com": "Energy/Utilities",
    "worldoil.com": "Energy/Utilities",
    "xcelenergy.com": "Energy/Utilities",
    "oilprice.com": "Energy/Utilities",
    "petrobras.com": "Energy/Utilities",
    "ppl.com": "Energy/Utilities",
    "rigzone.com": "Energy/Utilities",
    "emera.com": "Energy/Utilities",
    "idacorp.com": "Energy/Utilities",
    "centerpoint.com": "Energy/Utilities",
    "centerpointenergy.com": "Energy/Utilities",
    "energyvoice.com": "Energy/Utilities",
    "upstreamonline.com": "Energy/Utilities",
    # ------------------------------------------------------------------
    # Manufacturing
    # ------------------------------------------------------------------
    "3m.com": "Manufacturing",
    "abb.com": "Manufacturing",
    "airbus.com": "Manufacturing",
    "ametek.com": "Manufacturing",
    "basf.com": "Manufacturing",
    "boeing.com": "Manufacturing",
    "bosch.com": "Manufacturing",
    "caterpillar.com": "Manufacturing",
    "corning.com": "Manufacturing",
    "cummins.com": "Manufacturing",
    "danaher.com": "Manufacturing",
    "dover.com": "Manufacturing",
    "dow.com": "Manufacturing",
    "dupont.com": "Manufacturing",
    "emerson.com": "Manufacturing",
    "ericsson.com": "Manufacturing",
    "flowserve.com": "Manufacturing",
    "ford.com": "Manufacturing",
    "fortive.com": "Manufacturing",
    "fujitsu.com": "Manufacturing",
    "ge.com": "Manufacturing",
    "generalmotors.com": "Manufacturing",
    "gm.com": "Manufacturing",
    "goodyear.com": "Manufacturing",
    "harman.com": "Manufacturing",
    "hitachi.com": "Manufacturing",
    "honda.com": "Manufacturing",
    "honeywell.com": "Manufacturing",
    "hubbell.com": "Manufacturing",
    "illinois-tool.com": "Manufacturing",
    "itw.com": "Manufacturing",
    "jabil.com": "Manufacturing",
    "johndeere.com": "Manufacturing",
    "komatsu.com": "Manufacturing",
    "leggett.com": "Manufacturing",
    "lg.com": "Manufacturing",
    "michelin.com": "Manufacturing",
    "mitsubishi.com": "Manufacturing",
    "motorola.com": "Manufacturing",
    "nec.com": "Manufacturing",
    "panasonic.com": "Manufacturing",
    "parker.com": "Manufacturing",
    "pentair.com": "Manufacturing",
    "raytheon.com": "Manufacturing",
    "rockwellautomation.com": "Manufacturing",
    "rolls-royce.com": "Manufacturing",
    "roper.com": "Manufacturing",
    "siemens.com": "Manufacturing",
    "steelcase.com": "Manufacturing",
    "textron.com": "Manufacturing",
    "thyssenkrupp.com": "Manufacturing",
    "toyota.com": "Manufacturing",
    "volkswagen.com": "Manufacturing",
    "volvo.com": "Manufacturing",
    "westinghouse.com": "Manufacturing",
    "whirlpool.com": "Manufacturing",
    "xerox.com": "Manufacturing",
    "xylem.com": "Manufacturing",
    # ------------------------------------------------------------------
    # Real Estate
    # ------------------------------------------------------------------
    "apartments.com": "Real Estate",
    "century21.com": "Real Estate",
    "cbre.com": "Real Estate",
    "coldwellbanker.com": "Real Estate",
    "compass.com": "Real Estate",
    "cushwake.com": "Real Estate",
    "cushmanwakefield.com": "Real Estate",
    "dotloop.com": "Real Estate",
    "homefinder.com": "Real Estate",
    "homelight.com": "Real Estate",
    "houzeo.com": "Real Estate",
    "jll.com": "Real Estate",
    "kw.com": "Real Estate",
    "loopnet.com": "Real Estate",
    "move.com": "Real Estate",
    "opendoor.com": "Real Estate",
    "prologis.com": "Real Estate",
    "realestate.com.au": "Real Estate",
    "realogy.com": "Real Estate",
    "realtor.com": "Real Estate",
    "redfin.com": "Real Estate",
    "rightmove.co.uk": "Real Estate",
    "savills.com": "Real Estate",
    "simonproperty.com": "Real Estate",
    "trulia.com": "Real Estate",
    "waltersimonads.com": "Real Estate",
    "wework.com": "Real Estate",
    "xome.com": "Real Estate",
    "yearbook.com": "Real Estate",  # wrong — placeholder
    "zillow.com": "Real Estate",
    "zumper.com": "Real Estate",
    # ------------------------------------------------------------------
    # Agriculture/Food
    # ------------------------------------------------------------------
    "adm.com": "Agriculture/Food",
    "aldi.com": "Agriculture/Food",
    "burgerking.com": "Agriculture/Food",
    "bunge.com": "Agriculture/Food",
    "chick-fil-a.com": "Agriculture/Food",
    "chickfila.com": "Agriculture/Food",
    "chipotle.com": "Agriculture/Food",
    "coca-cola.com": "Agriculture/Food",
    "cocacola.com": "Agriculture/Food",
    "corteva.com": "Agriculture/Food",
    "danone.com": "Agriculture/Food",
    "deliveroo.com": "Agriculture/Food",
    "dominos.com": "Agriculture/Food",
    "doordash.com": "Agriculture/Food",
    "dunkindonuts.com": "Agriculture/Food",
    "dunkin.com": "Agriculture/Food",
    "elanco.com": "Agriculture/Food",
    "foodnetwork.com": "Agriculture/Food",
    "general-mills.com": "Agriculture/Food",
    "generalmills.com": "Agriculture/Food",
    "grubhub.com": "Agriculture/Food",
    "heinz.com": "Agriculture/Food",
    "hersheys.com": "Agriculture/Food",
    "ihop.com": "Agriculture/Food",
    "just-eat.com": "Agriculture/Food",
    "justeat.com": "Agriculture/Food",
    "kelloggs.com": "Agriculture/Food",
    "kfc.com": "Agriculture/Food",
    "kraftheinz.com": "Agriculture/Food",
    "kroger.com": "Agriculture/Food",
    "landolakes.com": "Agriculture/Food",
    "mars.com": "Agriculture/Food",
    "mccormick.com": "Agriculture/Food",
    "mcdonalds.com": "Agriculture/Food",
    "mondelez.com": "Agriculture/Food",
    "monsanto.com": "Agriculture/Food",
    "nestle.com": "Agriculture/Food",
    "panera.com": "Agriculture/Food",
    "pepsico.com": "Agriculture/Food",
    "pizzahut.com": "Agriculture/Food",
    "postmates.com": "Agriculture/Food",
    "starbucks.com": "Agriculture/Food",
    "subway.com": "Agriculture/Food",
    "swiggy.com": "Agriculture/Food",
    "sysco.com": "Agriculture/Food",
    "syngenta.com": "Agriculture/Food",
    "tastytrade.com": "Finance",        # not food — override
    "tysonfoods.com": "Agriculture/Food",
    "ubereats.com": "Agriculture/Food",
    "unilever.com": "Agriculture/Food",
    "wholefoods.com": "Agriculture/Food",
    "yum.com": "Agriculture/Food",
    "zomato.com": "Agriculture/Food",
    "tacobell.com": "Agriculture/Food",
    "papajohns.com": "Agriculture/Food",
    "dairyqueen.com": "Agriculture/Food",
    "olivegarden.com": "Agriculture/Food",
    "applebees.com": "Agriculture/Food",
    "jollibee.com": "Agriculture/Food",
    "arbys.com": "Agriculture/Food",
    # ------------------------------------------------------------------
    # Legal
    # ------------------------------------------------------------------
    "abajournal.com": "Legal",
    "allenovery.com": "Legal",
    "americanbar.org": "Legal",
    "ashurst.com": "Legal",
    "avvo.com": "Legal",
    "bailii.org": "Legal",
    "bakermckenzie.com": "Legal",
    "canlii.org": "Legal",
    "cliffordchance.com": "Legal",
    "clio.com": "Legal",
    "courtlistener.com": "Legal",
    "cravath.com": "Legal",
    "davispolk.com": "Legal",
    "dentons.com": "Legal",
    "disco.com": "Legal",
    "dlapiper.com": "Legal",
    "donotpay.com": "Legal",
    "everlaw.com": "Legal",
    "findlaw.com": "Legal",
    "freshfields.com": "Legal",
    "hg.org": "Legal",
    "herbertsmithfreehills.com": "Legal",
    "justia.com": "Legal",
    "kirkland.com": "Legal",
    "latham.com": "Legal",
    "law.com": "Legal",
    "law360.com": "Legal",
    "lawdepot.com": "Legal",
    "lawyer.com": "Legal",
    "legalzoom.com": "Legal",
    "lexisnexis.com": "Legal",
    "linklaters.com": "Legal",
    "martindale.com": "Legal",
    "mycase.com": "Legal",
    "nolo.com": "Legal",
    "nortonrosefulbright.com": "Legal",
    "paulweiss.com": "Legal",
    "relativity.com": "Legal",
    "rocket-lawyer.com": "Legal",
    "rocketlawyer.com": "Legal",
    "scotusblog.com": "Legal",
    "skadden.com": "Legal",
    "slaughterandmay.com": "Legal",
    "sullcrom.com": "Legal",
    "uscourts.gov": "Legal",
    "weil.com": "Legal",
    "westlaw.com": "Legal",
    "whitecase.com": "Legal",
    "wilsonsonsini.com": "Legal",
    "winston.com": "Legal",
    "wolterskluwer.com": "Legal",
    "hklaw.com": "Legal",
    "sidley.com": "Legal",
    "foley.com": "Legal",
    "cooley.com": "Legal",
    "orrick.com": "Legal",
    "mwe.com": "Legal",
    "fenwick.com": "Legal",
    "pillsbury.com": "Legal",
    "venable.com": "Legal",
    "finnegan.com": "Legal",
    "legalmatch.com": "Legal",
    "lawinsider.com": "Legal",
    # ------------------------------------------------------------------
    # Professional Services
    # ------------------------------------------------------------------
    "accenture.com": "Professional Services",
    "adp.com": "Professional Services",
    "aecom.com": "Professional Services",
    "aflac.com": "Professional Services",
    "alixpartners.com": "Professional Services",
    "aon.com": "Professional Services",
    "bain.com": "Professional Services",
    "bcg.com": "Professional Services",
    "boozallen.com": "Professional Services",
    "capgemini.com": "Professional Services",
    "cgi.com": "Professional Services",
    "cognizant.com": "Professional Services",
    "conduent.com": "Professional Services",
    "deloitte.com": "Professional Services",
    "dxc.com": "Professional Services",
    "egon-zehnder.com": "Professional Services",
    "ey.com": "Professional Services",
    "fticonsulting.com": "Professional Services",
    "gallup.com": "Professional Services",
    "gartner.com": "Professional Services",
    "hcltechnologies.com": "Professional Services",
    "huron.com": "Professional Services",
    "icf.com": "Professional Services",
    "idc.com": "Professional Services",
    "infosys.com": "Professional Services",
    "kearney.com": "Professional Services",
    "kornferry.com": "Professional Services",
    "kpmg.com": "Professional Services",
    "leidos.com": "Professional Services",
    "marsh.com": "Professional Services",
    "mckinsey.com": "Professional Services",
    "mercer.com": "Professional Services",
    "milliman.com": "Professional Services",
    "moodys.com": "Professional Services",
    "oliverwyman.com": "Professional Services",
    "paychex.com": "Professional Services",
    "pwc.com": "Professional Services",
    "randstad.com": "Professional Services",
    "sapient.com": "Professional Services",
    "shl.com": "Professional Services",
    "spencerstuart.com": "Professional Services",
    "spglobal.com": "Professional Services",
    "tata.com": "Professional Services",
    "tcs.com": "Professional Services",
    "technipfmc.com": "Professional Services",
    "towerswatson.com": "Professional Services",
    "unisys.com": "Professional Services",
    "wipro.com": "Professional Services",
    "woodmac.com": "Professional Services",
    "bureauveritas.com": "Professional Services",
    "dnv.com": "Professional Services",
    "intertek.com": "Professional Services",
    "ipsos.com": "Professional Services",
    "iqvia.com": "Professional Services",
    "kantar.com": "Professional Services",
    "nielsen.com": "Professional Services",
    "protiviti.com": "Professional Services",
    "sgs.com": "Professional Services",
    "verisk.com": "Professional Services",
    # ------------------------------------------------------------------
    # Nonprofit
    # ------------------------------------------------------------------
    "aclu.org": "Nonprofit",
    "actionaid.org": "Nonprofit",
    "americanredcross.org": "Nonprofit",
    "amnesty.org": "Nonprofit",
    "archive.org": "Nonprofit",
    "britannica.com": "Nonprofit",
    "care.org": "Nonprofit",
    "change.org": "Nonprofit",
    "charitywater.org": "Nonprofit",
    "childrensdefense.org": "Nonprofit",
    "conservation.org": "Nonprofit",
    "creativecommons.org": "Nonprofit",
    "doctorswithoutborders.org": "Nonprofit",
    "feedingamerica.org": "Nonprofit",
    "fidelitycharitable.org": "Nonprofit",
    "fordfoundation.org": "Nonprofit",
    "fsf.org": "Nonprofit",
    "gatesfoundation.org": "Nonprofit",
    "globalgiving.org": "Nonprofit",
    "goodwill.org": "Nonprofit",
    "greenpeace.org": "Nonprofit",
    "habitat.org": "Nonprofit",
    "ietf.org": "Nonprofit",
    "ieee.org": "Nonprofit",
    "iso.org": "Nonprofit",
    "kiva.org": "Nonprofit",
    "mercycorps.org": "Nonprofit",
    "msf.org": "Nonprofit",
    "nrdc.org": "Nonprofit",
    "openstreetmap.org": "Nonprofit",
    "oxfam.org": "Nonprofit",
    "plannedparenthood.org": "Nonprofit",
    "povertyactionlab.org": "Nonprofit",
    "redcross.org": "Nonprofit",
    "rotary.org": "Nonprofit",
    "salvationarmy.org": "Nonprofit",
    "savethechildren.org": "Nonprofit",
    "sierraclub.org": "Nonprofit",
    "thenatureconservancy.org": "Nonprofit",
    "unicef.org": "Nonprofit",
    "unesco.org": "Nonprofit",
    "unitedway.org": "Nonprofit",
    "weforum.org": "Nonprofit",
    "wikimedia.org": "Nonprofit",
    "worldbank.org": "Nonprofit",
    "worldwildlife.org": "Nonprofit",
    "wri.org": "Nonprofit",
    "wwf.org": "Nonprofit",
    "ymca.org": "Nonprofit",
    "ywca.org": "Nonprofit",
    "doctorswithoutborders.com": "Nonprofit",
    "heifer.org": "Nonprofit",
    "directrelief.org": "Nonprofit",
    "stjude.org": "Nonprofit",
    # ------------------------------------------------------------------
    # Sports
    # ------------------------------------------------------------------
    "247sports.com": "Sports",
    "adidas.com": "Sports",
    "athletic.net": "Sports",
    "ausopen.com": "Sports",
    "bein.com": "Sports",
    "bleacherreport.com": "Sports",
    "bundesliga.com": "Sports",
    "cbssports.com": "Sports",
    "chess.com": "Sports",
    "cricinfo.com": "Sports",
    "dazngroup.com": "Sports",
    "draftkings.com": "Sports",
    "espn.com": "Sports",
    "eurosport.com": "Sports",
    "f1.com": "Sports",
    "fanatics.com": "Sports",
    "fanduel.com": "Sports",
    "fifa.com": "Sports",
    "formula1.com": "Sports",
    "foxsports.com": "Sports",
    "goal.com": "Sports",
    "icc-cricket.com": "Sports",
    "laliga.com": "Sports",
    "masters.com": "Sports",
    "mlb.com": "Sports",
    "mlssoccer.com": "Sports",
    "motogp.com": "Sports",
    "motorsport.com": "Sports",
    "nba.com": "Sports",
    "nbcsports.com": "Sports",
    "nfl.com": "Sports",
    "nhl.com": "Sports",
    "olympics.com": "Sports",
    "pga.com": "Sports",
    "pgatour.com": "Sports",
    "premierleague.com": "Sports",
    "reebok.com": "Sports",
    "skysports.com": "Sports",
    "sofascore.com": "Sports",
    "sportradar.com": "Sports",
    "sportingnews.com": "Sports",
    "sportsillustrated.com": "Sports",
    "tennisabstract.com": "Sports",
    "theathletic.com": "Sports",
    "transfermarkt.com": "Sports",
    "ufc.com": "Sports",
    "uefa.com": "Sports",
    "ussoccer.com": "Sports",
    "wimbledon.com": "Sports",
    "worldathletics.org": "Sports",
    "worldrugby.org": "Sports",
    "wwe.com": "Sports",
    # ------------------------------------------------------------------
    # Gaming
    # ------------------------------------------------------------------
    "2k.com": "Gaming",
    "activision.com": "Gaming",
    "bandainamco.com": "Gaming",
    "bethesda.net": "Gaming",
    "blizzard.com": "Gaming",
    "capcom.com": "Gaming",
    "cdprojektred.com": "Gaming",
    "crazygames.com": "Gaming",
    "cursedcraft.net": "Gaming",
    "ea.com": "Gaming",
    "epicgames.com": "Gaming",
    "epicgames.dev": "Gaming",
    "fandom.com": "Gaming",
    "gamepass.com": "Gaming",
    "gog.com": "Gaming",
    "ign.com": "Gaming",
    "konami.com": "Gaming",
    "leagueoflegends.com": "Gaming",
    "mojang.com": "Gaming",
    "namco.com": "Gaming",
    "nexusmods.com": "Gaming",
    "nintendo.com": "Gaming",
    "nintendo.net": "Gaming",
    "overwolf.com": "Gaming",
    "playstation.com": "Gaming",
    "playstation.net": "Gaming",
    "polygon.com": "Gaming",
    "primevideo.com": "Gaming",   # actually streaming/media -- override
    "riot.com": "Gaming",
    "riotgames.com": "Gaming",
    "roblox.com": "Gaming",
    "rockstargames.com": "Gaming",
    "segasammy.com": "Gaming",
    "sega.com": "Gaming",
    "squareenix.com": "Gaming",
    "steam.com": "Gaming",
    "steamcommunity.com": "Gaming",
    "steampowered.com": "Gaming",
    "supercell.com": "Gaming",
    "taktwogames.com": "Gaming",
    "take2games.com": "Gaming",
    "twitch.tv": "Gaming",
    "ubisoftconnect.com": "Gaming",
    "ubisoft.com": "Gaming",
    "unity3d.com": "Gaming",
    "unity.com": "Gaming",
    "valve.com": "Gaming",
    "xbox.com": "Gaming",
    "xboxlive.com": "Gaming",
    "xboxgamestudios.com": "Gaming",
    "zynga.com": "Gaming",
    # ------------------------------------------------------------------
    # Social Media
    # ------------------------------------------------------------------
    "bsky.app": "Social Media",
    "buffer.com": "Social Media",
    "discord.com": "Social Media",
    "discord.gg": "Social Media",
    "facebook.com": "Social Media",
    "fb.com": "Social Media",
    "instagram.com": "Social Media",
    "kik.com": "Social Media",
    "letterboxd.com": "Social Media",
    "line.me": "Social Media",
    "linkedin.com": "Social Media",
    "mastodon.social": "Social Media",
    "medium.com": "Social Media",
    "mewe.com": "Social Media",
    "myspace.com": "Social Media",
    "ok.ru": "Social Media",
    "parler.com": "Social Media",
    "pinterest.com": "Social Media",
    "quora.com": "Social Media",
    "reddit.com": "Social Media",
    "signal.org": "Social Media",
    "sina.com.cn": "Social Media",
    "snapchat.com": "Social Media",
    "t.me": "Social Media",
    "telegram.me": "Social Media",
    "telegram.org": "Social Media",
    "threads.com": "Social Media",
    "tiktok.com": "Social Media",
    "truth-social.com": "Social Media",
    "truthsocial.com": "Social Media",
    "tumblr.com": "Social Media",
    "twitter.com": "Social Media",
    "vk.com": "Social Media",
    "vkontakte.ru": "Social Media",
    "wa.me": "Social Media",
    "weibo.com": "Social Media",
    "wechat.com": "Social Media",
    "whatsapp.com": "Social Media",
    "whatsapp.net": "Social Media",
    "x.com": "Social Media",
    "xiaohongshu.com": "Social Media",
    "youtube.com": "Social Media",
    # ------------------------------------------------------------------
    # Science/Research
    # ------------------------------------------------------------------
    "acm.org": "Science/Research",
    "acs.org": "Science/Research",
    "annualreviews.org": "Science/Research",
    "aps.org": "Science/Research",
    "arxiv.org": "Science/Research",
    "biomedcentral.com": "Science/Research",
    "biorxiv.org": "Science/Research",
    "bmj.com": "Science/Research",
    "cell.com": "Science/Research",
    "chemrxiv.org": "Science/Research",
    "dimensions.ai": "Science/Research",
    "doi.org": "Science/Research",
    "elsevier.com": "Science/Research",
    "embo.org": "Science/Research",
    "europepmc.org": "Science/Research",
    "figshare.com": "Science/Research",
    "frontiersin.org": "Science/Research",
    "hindawi.com": "Science/Research",
    "iop.org": "Science/Research",
    "jmir.org": "Science/Research",
    "jstor.org": "Science/Research",
    "lancet.com": "Science/Research",
    "mdpi.com": "Science/Research",
    "medrxiv.org": "Science/Research",
    "nature.com": "Science/Research",
    "nejm.org": "Science/Research",
    "newscientist.com": "Science/Research",
    "oup.com": "Science/Research",
    "phys.org": "Science/Research",
    "physicsworld.com": "Science/Research",
    "plos.org": "Science/Research",
    "pnas.org": "Science/Research",
    "quantamagazine.org": "Science/Research",
    "researchgate.net": "Science/Research",
    "royalsociety.org": "Science/Research",
    "rsc.org": "Science/Research",
    "sagepub.com": "Science/Research",
    "sciencealert.com": "Science/Research",
    "sciencedirect.com": "Science/Research",
    "sciencemag.org": "Science/Research",
    "sciencenews.org": "Science/Research",
    "semanticscholar.org": "Science/Research",
    "springer.com": "Science/Research",
    "ssrn.com": "Science/Research",
    "tandfonline.com": "Science/Research",
    "wiley.com": "Science/Research",
    "wolframalpha.com": "Science/Research",
    "zenodo.org": "Science/Research",
    "zotero.org": "Science/Research",
}

# Remove placeholder/wrong entries added above (clean up collisions)
_OVERRIDES = {
    "clevelandclinic.org": "Healthcare",
    "wsj.com": "Finance",
    "target.com": "Retail/Ecommerce",
    "airbnb.com": "Travel/Hospitality",
    "primevideo.com": "Media/News",
    "nytimes.com": "Media/News",
    "chess.com": "Sports",  # sports before gaming in SECTORS list
    "ge.com": "Manufacturing",
    "philips.com": "Healthcare",
    "basf.com": "Manufacturing",
}
DOMAIN_MAP.update(_OVERRIDES)

# Remove known-bad placeholder entries
_REMOVE = {
    "brilliantearth.com",
    "yearbook.com",
    "rollsstats.com",
    "rowlands.com",
    "marscandybar.com",
    "nestlé.com",
    "cursedcraft.net",
    "taktwogames.com",
    "samsung.com/shop",
    "mariott.com",
}
for _d in _REMOVE:
    DOMAIN_MAP.pop(_d, None)

# ---------------------------------------------------------------------------
# Tier 2 — TLD rules
# ---------------------------------------------------------------------------
GOV_TLDS = re.compile(
    r"(\.(gov|mil)"
    r"|\.gov\.(au|br|cn|in|sg|uk|za|nz|ph|my|gh|ng|pk|bd|eg|il|ar|mx|co)"
    r"|\.gouv\.fr|\.gob\.(mx|es|ar)|\.govt\.nz"
    r"|\.gc\.ca|\.mod\.uk|\.service\.gov\.uk"
    r")$"
)
EDU_TLDS = re.compile(
    r"(\.(edu)"
    r"|\.edu\.(au|br|cn|eg|gh|in|mx|my|ng|ph|pk|sg|tr|tw|za)"
    r"|\.ac\.(uk|nz|za|jp|kr|in|bd|il|ae)"
    r"|\.sch\.uk"
    r")$"
)

# ---------------------------------------------------------------------------
# Tier 3 — Keyword patterns (last resort, lower confidence)
#
# Patterns are intentionally narrow to minimise false positives:
#   - Require compound or unambiguous terms (e.g. "real-estate" not "estate")
#   - Avoid generic substrings that appear in unrelated domains
#     ("power" → PowerPoint, "gas" → xorgasmo, "rail" → callrail, etc.)
#   - Each pattern has a comment noting what it does NOT match
# ---------------------------------------------------------------------------

# Domains that produce false positives from keyword matching — these are
# excluded from tier3 classification regardless of keyword matches.
KEYWORD_BLOCKLIST: frozenset[str] = frozenset({
    # "power*" false positives (Microsoft, ad-tech, reviews, gambling)
    "powerbi.com", "powerapps.com", "powerplatform.com", "powerreviews.com",
    "paddypower.com", "adspower.net", "wpenginepowered.com", "manpower.com",
    # "gas" false positives
    "xorgasmo.com", "nregastrep.nic.in", "clickpetroleoegas.com.br",
    # "rail*" false positives (call-tracking, software, hiking)
    "callrail.com", "technorail.com", "alltrails.com",
    # "delivery" false positives (CDN / ad-delivery)
    "aiv-delivery.net", "ad-delivery.net", "captcha-delivery.com",
    # "estate" false positives (software, RTB)
    "activestate.com", "brealtime.com", "ably-realtime.com",
    # "condo" false positives (Japanese fashion)
    "locondo.jp",
    # "realt*" false positives (RTB / real-time ad platforms)
    "realtimeregister.com",
    # "seed*" false positives (ad-tech tag manager)
    "seedtag.com",
    # "chef" false positives (CDN with 'chef' substring in name)
    "cachefly.net",
    # "farm*" false positives (insurance)
    "statefarm.com",
    # "chef" false positives (Apache software project)
    "apachefriends.org",
    # "law" false positives (cookie consent)
    "cookielaw.org",
    # "rental" false positives (car rental classified under travel)
    "rentalcars.com",
    # ".rehab" / ".dental" TLD abuse by piracy sites — not healthcare
    "hdhub4u.rehab",
    "5movierulz.dental",
    # "ngonetwork" false positive (Play'n GO gaming company)
    "playngonetwork.com",
    # adult content site matching "socialmedia*"
    "socialmediagirls.com",
    # live-sports streaming sites that match "esport" substring in "livesport"
    "livesport.cz",
    "livesports088.com",
    "livesportmedia.eu",
    "livesport.services",
    "livesport.com",
    "telesport.co.il",
    # sports editorial site (not a gaming platform)
    "givemesport.com",
    # news network matching "esport" (sports news, not gaming)
    "ngengesport.cd",
})

KEYWORD_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Finance: require dedicated finance terms; avoid generic "capital" (too broad for
    # tech VC names), "credit" (too broad — creditcards.com vs. creditcard fraud tools)
    (re.compile(r"((?<!\w)bank(?!width)|financ(?:e|ial)|invest(?:ment|ing)|forex|brokerage|mutual.?fund|stock.?exchange|cryptocurrency|(?<!\w)insur(?:ance)?(?!\w))", re.I), "Finance"),

    # Healthcare: compound forms only; avoid "clinic" matching "clinicaltrials" (research)
    (re.compile(r"(healthcare|healthgrades|medicalcenter|pharma(?:cy|ceutical)|hospital(?:ity)?(?=\b)|dental(?:care)?|nursing(?:home)?|rehab(?:ilitation)?|biotech(?:nology)?|telemedicine)", re.I), "Healthcare"),

    # Education: unambiguous compound forms
    (re.compile(r"(university|college(?=\.)|e-learning|online.?course|tutoring|scholarship|elearning)", re.I), "Education"),

    # Telecommunications: avoid "mobile" (matches mobile-friendly tech sites)
    (re.compile(r"(telecom(?:munication)?|wireless(?:carrier)?|broadband(?:provider)?|(?<!\w)isp(?!\w)|cellular(?:network)?|mobileoperator)", re.I), "Telecommunications"),

    # Media/News: avoid "times" (too common), require news-specific compounds
    (re.compile(r"(breaking.?news|newsroom|newsagency|thenews|liveradio|podcast(?:network)?|tvnetwork|broadcaster|newswire|pressrelease)", re.I), "Media/News"),

    # Retail/Ecommerce: avoid "market" (too broad — financial markets, supermarkets mix)
    (re.compile(r"(ecommerce|e-commerce|onlineshop|supermarket|shoppingmall|retailer|(?<!\w)checkout(?!\w)|webstore|shopfront)", re.I), "Retail/Ecommerce"),

    # Travel: avoid "tour" (matches software tours, product tours)
    (re.compile(r"((?<!\w)hotel(?:s)?(?!\w)|hostel(?:world)?|(?<!\w)resort(?:s)?(?!\w)|vacation(?:rental)?|flightbook|airlineticket|cruiseline|travelagenc)", re.I), "Travel/Hospitality"),

    # Transportation: avoid generic "delivery" (CDN / ad delivery); avoid bare "rail"
    # (callrail); require transport-specific compounds
    (re.compile(r"(freightline|cargoship|logistics(?:company)?|shipping(?:company|line)|courierservice|railwaynetwork|railwaystation|transitauthority|trucking(?:company)?|(?<!\w)parcelservice)", re.I), "Transportation"),

    # Energy/Utilities: avoid "power" alone (Microsoft Power Platform, ad-tech)
    # require compound: power-grid, powerplant, powergenerator, etc.
    (re.compile(r"((?<!\w)energycompany|power(?:grid|plant|station|generator|utility)|electricgrid|electricutility|naturalgas(?:company)?|oilgas|petroleum(?:company)?|nuclearenergy|solarenergy|windenergy|electricpower|utilitycompany)", re.I), "Energy/Utilities"),

    # Manufacturing: unambiguous industrial terms
    (re.compile(r"(manufactur(?:ing|er)|industrialequip|assemblyline|fabricat(?:ion)?|aerospacecompany|automotivemanuf|machinerymaker)", re.I), "Manufacturing"),

    # Real Estate: require "real.?estate" compound; avoid bare "estate", "property",
    # "realt*" (RTB platforms use "realtime")
    (re.compile(r"(real.?estate|realtor(?:\.com|\.ca|\.au)?|realestate|propertymarket|housingmarket|mortgagerate|apartmentfinder|condosal)", re.I), "Real Estate"),

    # Agriculture/Food: avoid bare "seed" (ad-tech), "chef" (CDN substring),
    # "farm" alone (State Farm insurance)
    (re.compile(r"((?<!\w)agri(?:culture|cultural|tech)|farming(?:news|guide|equipment)|cropscience|foodnetwork|restaurant(?:guide|finder)|fooddelivery|grocerystore|beveragecompany|nutritionguide|chefstable|dairyfarm|livestockfarming)", re.I), "Agriculture/Food"),

    # Legal: avoid bare "law" (cookielaw, bylaw, outlaw); require legal-specific compounds
    (re.compile(r"(legalservices|legaladvice|lawfirm|lawschool|attorney(?:general)?|(?<!\w)lawyers?\.(?:com|org|net)|courtrecords?|justicedept|solicitorgeneral|barrister|paralegal|litigation(?:support)?)", re.I), "Legal"),

    # Professional Services: avoid "tax" alone (taxation in domain name is rare but
    # "tax" appears in many unrelated names)
    (re.compile(r"(management(?:consulting|consultancy)|businessadvisory|accountingfirm|auditfirm|staffingagency|recruitmentfirm|outsourcing(?:company)?|hrservice|payrollservice)", re.I), "Professional Services"),

    # Nonprofit: require dedicated nonprofit indicators
    (re.compile(r"((?<!\w)nonprofit|notforprofit|charitable(?:org|foundation)?|ngonetwork|humanitarianaid|volunteerplatform|philanthropyfund)", re.I), "Nonprofit"),

    # Sports: specific sports bodies / terminology
    (re.compile(r"((?<!\w)sports?(?:network|news|league|center|club)|football(?:club|league)|soccerleague|basketballleague|baseballleague|tennistournament|cricketboard|golfcourse|olympicgames|athleticsclub|esportleague|nflnetwork|nbanetwork)", re.I), "Sports"),

    # Gaming: avoid "game" alone (too many false positives)
    (re.compile(r"(gamingnews|esport(?:s)?(?:network)?|gamerstudio|videogame(?:s)?|onlinegaming|mobilegaming|gamepass|gamingplatform|streamergame)", re.I), "Gaming"),

    # Social Media: require social-specific compounds
    (re.compile(r"(socialmedia|socialnetwork|microblog|messagingapp|datingapp|onlineforum(?:\.)|communityplatform)", re.I), "Social Media"),

    # Science/Research: require academic publication or research compound
    (re.compile(r"(scientificjournal|researchinstitute|academicpublish|preprint(?:server)?|openaccess(?:journal)?|peerreview|scientificpublish|researchlab)", re.I), "Science/Research"),
]


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------
def classify(domain: str) -> tuple[str, str, str] | None:
    """
    Returns (sector, tier, basis) or None if unclassified.
    """
    # Tier 1
    if domain in DOMAIN_MAP:
        return DOMAIN_MAP[domain], "tier1_explicit", "curated dictionary"

    # Tier 2
    if GOV_TLDS.search(domain):
        return "Government", "tier2_tld", "TLD matches government pattern"
    if EDU_TLDS.search(domain):
        return "Education", "tier2_tld", "TLD matches education pattern"

    # Tier 3 (blocklist check first)
    if domain not in KEYWORD_BLOCKLIST:
        for pattern, sector in KEYWORD_PATTERNS:
            m = pattern.search(domain)
            if m:
                return sector, "tier3_keyword", f"keyword '{m.group(0)}' in domain"

    return None


# ---------------------------------------------------------------------------
# Download Tranco list
# ---------------------------------------------------------------------------
def download_tranco(url: str, top_n: int) -> list[tuple[int, str]]:
    print(f"Downloading Tranco list (top {top_n:,}) from {url} …", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "paper02-research/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        try:
            rank = int(parts[0])
        except ValueError:
            continue
        rows.append((rank, parts[1].strip().lower()))
    print(f"  Parsed {len(rows):,} rows.", flush=True)
    return rows


# ---------------------------------------------------------------------------
# Build sector samples
# ---------------------------------------------------------------------------
def build_samples(rows: list[tuple[int, str]]) -> dict[str, list[dict]]:
    buckets: dict[str, list[dict]] = {s: [] for s in SECTORS}
    assigned: set[str] = set()

    for rank, domain in rows:
        if domain in assigned:
            continue
        result = classify(domain)
        if result is None:
            continue
        sector, tier, basis = result
        if sector not in buckets:
            continue
        if len(buckets[sector]) >= SAMPLES_PER_SECTOR:
            continue
        buckets[sector].append({
            "rank": rank,
            "domain": domain,
            "sector": sector,
            "classification_tier": tier,
            "classification_basis": basis,
        })
        assigned.add(domain)

        # Stop early if all sectors are full
        if all(len(v) >= SAMPLES_PER_SECTOR for v in buckets.values()):
            break

    return buckets


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    rows = download_tranco(TRANCO_URL, TOP_N_DOWNLOAD)

    print("Classifying domains into sectors …", flush=True)
    buckets = build_samples(rows)

    # Summary
    print("\nSector fill (target 50 each):")
    short = []
    for sector in SECTORS:
        n = len(buckets[sector])
        status = "OK" if n >= SAMPLES_PER_SECTOR else f"SHORT ({n})"
        print(f"  {sector:<30} {n:>3}  {status}")
        if n < SAMPLES_PER_SECTOR:
            short.append(sector)

    output = {
        "metadata": {
            "tranco_list_id": TRANCO_LIST_ID,
            "tranco_date": TRANCO_DATE,
            "tranco_config": "Dowdall method; providers: Crux, Farsight, Majestic, Radar, Umbrella",
            "tranco_download_url": TRANCO_URL,
            "tranco_archive_url": f"https://tranco-list.eu/list/{TRANCO_LIST_ID}/full",
            "tranco_citation": (
                "Le Pochat, V. et al. (2019). Tranco: A Research-Oriented Top Sites "
                "Ranking Hardened Against Manipulation. NDSS 2019. "
                "DOI: 10.14722/ndss.2019.23386"
            ),
            "classification_method": (
                "Three-tier: Tier 1 = explicit curated domain dictionary; "
                "Tier 2 = TLD pattern rules (.gov/.mil → Government, .edu → Education); "
                "Tier 3 = domain-name keyword heuristics. "
                "Each domain assigned to at most one sector (first match in rank order)."
            ),
            "classification_caveat": (
                "Sector assignments are best-effort and may not be perfectly accurate "
                "in every case, particularly for Tier-3 keyword-matched entries where "
                "a domain name contains a sector keyword without the organisation being "
                "a primary actor in that sector. "
                "The classification is intentionally broad: the purpose of this sample "
                "is not to audit any specific organisation, but to assess the overall "
                "state of industry readiness for the transition to post-quantum "
                "cryptography (PQC) across a representative cross-section of 21 sectors. "
                "Sector-level aggregate findings (cipher suite distribution, TLS version "
                "adoption, absence of PQC key exchange) are robust to individual "
                "misclassifications because the signal of interest — zero or near-zero "
                "PQC adoption — is expected to hold across all sectors regardless of "
                "precise organisational categorisation."
            ),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "total_tranco_rows_scanned": len(rows),
            "samples_per_sector_target": SAMPLES_PER_SECTOR,
            "sectors_short": short,
            "total_domains_selected": sum(len(v) for v in buckets.values()),
        },
        "sectors": buckets,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\nWrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    print(f"Total domains selected: {output['metadata']['total_domains_selected']}")
    if short:
        print(f"WARNING: {len(short)} sector(s) below target 50: {short}")
        sys.exit(1)


if __name__ == "__main__":
    main()
