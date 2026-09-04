"""
kev.py

This module communicates with CISA's Known Exploited Vulnerabilities
(KEV) Catalog.

The KEV catalog contains vulnerabilities that are known to have been
exploited in the real world.

Our automation will use this information to answer:

    "Is this CVE known to have been exploited?"

This is important because CVSS tells us how severe a vulnerability
COULD be.

KEV information tells us whether exploitation has actually been
observed and recognized in the KEV catalog.

Conceptually:

    CVSS
      ↓
"How bad could this vulnerability be?"

    KEV
      ↓
"Is this vulnerability known to have been exploited?"
"""


# requests allows Python to download information from web APIs
# and web-accessible data sources.
import requests


# ------------------------------------------------------------
# CISA KEV CATALOG URL
# ------------------------------------------------------------

# CISA provides its Known Exploited Vulnerabilities catalog in
# machine-readable formats, including JSON.
#
# This URL is the JSON catalog used by our automation.
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def get_kev_catalog():
    """
    Download the CISA Known Exploited Vulnerabilities catalog.

    Returns:
        dict:
            The full KEV catalog as Python dictionary data.

        None:
            If the catalog could not be downloaded.
    """

    try:

        print("[+] Downloading CISA KEV catalog...")

        response = requests.get(
            KEV_URL,
            timeout=30,
        )


        # Raise an exception if the server returned an HTTP error.
        response.raise_for_status()


        # Convert JSON into Python data.
        kev_data = response.json()


        # Extract the vulnerability list.
        vulnerabilities = kev_data.get(
            "vulnerabilities",
            [],
        )


        print(
            f"[+] CISA KEV catalog loaded successfully "
            f"({len(vulnerabilities)} vulnerabilities)."
        )


        return kev_data


    except requests.exceptions.RequestException as error:

        print(
            f"[!] Error while downloading the CISA KEV catalog: "
            f"{error}"
        )

        return None


def create_kev_lookup(kev_data):
    """
    Create a fast lookup dictionary.

    Instead of repeatedly searching through the entire KEV catalog,
    we create a dictionary like this:

        {
            "CVE-2021-44228": {...},
            "CVE-2017-0144": {...},
            "CVE-2024-40766": {...}
        }

    Then we can quickly ask:

        kev_lookup.get("CVE-2021-44228")

    Parameters:
        kev_data (dict):
            The full KEV catalog.

    Returns:
        dict:
            A dictionary where CVE IDs are the keys.
    """


    # If the catalog failed to download, return an empty lookup.
    if not kev_data:

        return {}


    # Get the list of KEV vulnerabilities.
    vulnerabilities = kev_data.get(
        "vulnerabilities",
        [],
    )


    # Create an empty dictionary.
    kev_lookup = {}


    # Go through every KEV vulnerability.
    for vulnerability in vulnerabilities:

        # Get the CVE ID.
        cve_id = vulnerability.get("cveID")


        # Only add valid CVE IDs.
        if cve_id:

            # Store the entire KEV record under its CVE ID.
            kev_lookup[cve_id] = vulnerability


    return kev_lookup


def check_kev(cve_id, kev_lookup):
    """
    Check whether a CVE exists in the KEV catalog.

    Parameters:
        cve_id (str):
            Example:

                "CVE-2021-44228"

        kev_lookup (dict):
            The fast lookup dictionary created by
            create_kev_lookup().

    Returns:
        tuple:

            (
                is_known_exploited,
                kev_details
            )

        Examples:

            (True, {...})

        or:

            (False, None)
    """


    # Look for the CVE ID in our KEV dictionary.
    kev_details = kev_lookup.get(cve_id)


    # If the CVE exists, it is known exploited.
    if kev_details:

        return True, kev_details


    # Otherwise, it was not found.
    return False, None


# ------------------------------------------------------------
# TEST SECTION
# ------------------------------------------------------------

if __name__ == "__main__":

    print("\n[+] Testing the KEV collector...\n")


    # --------------------------------------------------------
    # 1. Download the KEV catalog.
    # --------------------------------------------------------

    kev_data = get_kev_catalog()


    # Stop if the download failed.
    if not kev_data:

        print("[!] KEV test stopped because the catalog was unavailable.")


    else:

        # ----------------------------------------------------
        # 2. Create our fast CVE lookup.
        # ----------------------------------------------------

        kev_lookup = create_kev_lookup(
            kev_data
        )


        print(
            f"[+] KEV lookup created with "
            f"{len(kev_lookup)} CVE entries."
        )


        # ----------------------------------------------------
        # 3. Test a CVE known to be in KEV.
        # ----------------------------------------------------

        test_cve = "CVE-2017-0144"


        print(
            f"\n[+] Checking {test_cve}..."
        )


        is_exploited, details = check_kev(
            test_cve,
            kev_lookup,
        )


        print(
            f"Known Exploited: {is_exploited}"
        )


        # ----------------------------------------------------
        # 4. Display useful information if found.
        # ----------------------------------------------------

        if is_exploited:

            print()

            print(
                "Vendor / Project:",
                details.get(
                    "vendorProject",
                    "Unknown",
                ),
            )

            print(
                "Product:",
                details.get(
                    "product",
                    "Unknown",
                ),
            )

            print(
                "Date Added:",
                details.get(
                    "dateAdded",
                    "Unknown",
                ),
            )

            print(
                "Required Action:",
                details.get(
                    "requiredAction",
                    "Unknown",
                ),
            )


        else:

            print(
                f"{test_cve} was not found in the KEV catalog."
            )