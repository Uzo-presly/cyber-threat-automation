"""
vulnerabilities.py

This module communicates with the NVD (National Vulnerability Database)
API and retrieves recently published CVE records.

The functions here do NOT decide which vulnerabilities are most important.
That job will later belong to scorer.py.

Think of this file as the "collector":

    NVD API
       ↓
    vulnerabilities.py
       ↓
    Raw CVE information
"""


# requests allows Python to make HTTP requests to web APIs.
import requests

# os allows Python to read environment variables from the operating system.
import os

# Import the function responsible for saving our completed
# vulnerability decisions into a timestamped report file.
from report import save_report

# Import the report generator.
#
# report.py will save the final vulnerability decisions
# into timestamped files.
from report import create_report_file

# datetime helps us calculate a time window for "recent" vulnerabilities.
from datetime import datetime, timedelta, timezone


# Import our vulnerability prioritization functions from scorer.py.
# scorer.py is in the same directory as vulnerabilities.py,
# so Python can import the functions directly.
# Import functions responsible for CVSS-based scoring
# and final priority calculation.
from scorer import (
    calculate_priority,
    explain_priority,
    apply_kev_bonus,
    get_final_priority_label,
)
#this means "Python, go into scorer.py and bring me these two functions: calculate_priority, explain_priority"


# Import functions responsible for downloading the CISA
# Known Exploited Vulnerabilities catalog and checking CVEs.
from kev import (
    get_kev_catalog,
    create_kev_lookup,
    check_kev,
)


# Import the AI analysis function from summarizer.py.
#
# This allows vulnerabilities.py to send a real CVE
# to Gemini after collecting and prioritizing it.
from summarizer import summarize_vulnerability


# The official NVD CVE API endpoint.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_recent_vulnerabilities(hours=24, results_per_page=20):
    """
    Retrieve CVEs published within the last specified number of hours.

    Parameters:
        hours (int):
            How far back we want to search.

            Example:
                hours=24 means:
                "Give me vulnerabilities published during the last 24 hours."

        results_per_page (int):
            Maximum number of CVE results to request.

    Returns:
        list:
            A list containing CVE dictionaries.

            If something goes wrong, an empty list is returned.
    """


    # ------------------------------------------------------------
    # 1. Retrieve our API key from the Bash environment.
    # ------------------------------------------------------------

    # os.getenv() asks the operating system:
    #
    # "Do you have an environment variable called NVD_API_KEY?"
    #
    # If it exists, its value is returned.
    # If it does not exist, None is returned.
    nvd_api_key = os.getenv("NVD_API_KEY")


    # ------------------------------------------------------------
    # 2. Stop early if the API key was not found.
    # ------------------------------------------------------------

    if not nvd_api_key:
        print("[!] NVD_API_KEY was not found.")

        print(
            "[!] Make sure your API key is exported in ~/.bashrc "
            "and reload Bash with:"
        )

        print("    source ~/.bashrc")

        return []


    # ------------------------------------------------------------
    # 3. Calculate our search time window.
    # ------------------------------------------------------------

    # Get the current time in UTC.
    end_time = datetime.now(timezone.utc)

    # Subtract the requested number of hours.
    start_time = end_time - timedelta(hours=hours)


    # ------------------------------------------------------------
    # 4. Convert Python time into the format expected by NVD.
    # ------------------------------------------------------------

    # NVD expects timestamps similar to:
    #
    # 2026-08-25T10:30:00.000 UTC
    #
    # We format our Python datetime objects accordingly.
    # Format the timestamps using ISO-8601 UTC notation.
    #
    # The trailing "Z" means:
    #
    #     This time is expressed in UTC.
    #
    # Example:
    #
    #     2026-08-25T12:30:00.000Z

    start_time_string = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    end_time_string = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")


    # ------------------------------------------------------------
    # 5. Prepare API query parameters.
    # ------------------------------------------------------------

    params = {
        "pubStartDate": start_time_string,
        "pubEndDate": end_time_string,
        "resultsPerPage": results_per_page,
    }


    # ------------------------------------------------------------
    # 6. Prepare HTTP request headers.
    # ------------------------------------------------------------

    # The NVD API accepts the API key in the apiKey header.
    headers = {
        "apiKey": nvd_api_key,
    }


    try:

        # --------------------------------------------------------
        # 7. Send the request to NVD.
        # --------------------------------------------------------

        print("[+] Contacting the NVD API...")

        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=30,
        )


        # --------------------------------------------------------
        # 8. Check whether the server returned an HTTP error.
        # --------------------------------------------------------

        # Examples:
        #
        # 200 = Success
        # 401 = Unauthorized
        # 403 = Forbidden
        # 404 = Not Found
        # 429 = Too many requests
        # 500 = Server error
        response.raise_for_status()


        # --------------------------------------------------------
        # 9. Convert the JSON response into a Python dictionary.
        # --------------------------------------------------------

        data = response.json()


        # --------------------------------------------------------
        # 10. Extract the vulnerability list.
        # --------------------------------------------------------

        vulnerabilities = data.get("vulnerabilities", [])


        # --------------------------------------------------------
        # 11. Report what we found.
        # --------------------------------------------------------

        print(
            f"[+] Found {len(vulnerabilities)} "
            f"recent vulnerabilities."
        )


        # Return the CVE records to whichever script called us.
        return vulnerabilities


    except requests.exceptions.RequestException as error:

        # If the request fails, explain what happened.
        print(f"[!] Error while contacting the NVD API: {error}")

        # Return an empty list so the rest of the program does not crash.
        return []


def display_vulnerabilities(vulnerabilities, kev_lookup):
    """
    Display CVE information and make a final priority decision.

    For every CVE, this function:

        1. Extracts the CVE ID.
        2. Extracts the English description.
        3. Extracts CVSS score and severity.
        4. Calculates the initial CVSS-based priority.
        5. Checks whether the CVE is known to be exploited.
        6. Applies a KEV priority bonus when appropriate.
        7. Calculates the final priority.
        8. Displays the complete decision.
    """
        # Create an empty list.
    #
    # Each analyzed CVE will be stored here as a dictionary.
    #
    # After all CVEs have been analyzed, this list will be
    # returned to the main program and sent to report.py.
    analyzed_vulnerabilities = []


    # If NVD returned no vulnerabilities, stop here.
    if not vulnerabilities:

        print("[!] No vulnerabilities were returned.")

        # Return an empty list because the main program
        # expects this function to return analyzed results.
        return []
           
        # --------------------------------------------------------
        # Load the CISA Known Exploited Vulnerabilities catalog.
        # --------------------------------------------------------
        #
        # We do this ONCE before processing all CVEs.
        #
        # The catalog will then be converted into a lookup structure
        # that allows us to quickly ask:
        #
        #     "Is this CVE known to be exploited?"
        # --------------------------------------------------------

        print()

        print("[+] Preparing CISA KEV information...")

        kev_catalog = get_kev_catalog()


        # Convert the KEV catalog into a faster lookup structure.
        # If the catalog was downloaded successfully,
        # convert it into a fast lookup dictionary.
        if kev_catalog:

            kev_lookup = create_kev_lookup(
                kev_catalog
            )


            print(
                f"[+] KEV lookup ready with "
                f"{len(kev_lookup)} CVE entries."
            )


        else:

            # If KEV could not be downloaded, create an empty
            # dictionary instead.
            #
            # This allows the rest of the vulnerability automation
            # to continue instead of crashing.
            kev_lookup = {}


            print(
                "[!] KEV catalog was unavailable. "
                "Continuing without KEV enrichment."
            )
        


    # --------------------------------------------------------
    # REPORT DATA COLLECTION
    # --------------------------------------------------------

    # This list will store the FINAL decisions made for
    # every vulnerability.
    #
    # At the end of the function, we will return this list
    # to the main program.
    report_vulnerabilities = []


    # Loop through every vulnerability returned by NVD.
    for item in vulnerabilities:

        # Each NVD result stores the CVE inside the "cve" key.
        cve = item.get("cve", {})


        # --------------------------------------------------------
        # 1. Extract the CVE ID.
        # --------------------------------------------------------

        cve_id = cve.get("id", "Unknown CVE")

        # --------------------------------------------------------
        # Extract the NVD publication date.
        # --------------------------------------------------------

        # NVD records contain the time when the CVE was
        # published in the NVD.
        published = cve.get(
            "published",
            "Unknown",
        )
        # --------------------------------------------------------
        # Create the official NVD verification link.
        # --------------------------------------------------------

        # Every CVE has its own official NVD detail page.
        #
        # Example:
        #
        # CVE-2026-12345
        #
        # becomes:
        #
        # https://nvd.nist.gov/vuln/detail/CVE-2026-12345
        nvd_link = (
            f"https://nvd.nist.gov/vuln/detail/"
            f"{cve_id}"
        )


        # --------------------------------------------------------
        # 2. Extract the English description.
        # --------------------------------------------------------

        descriptions = cve.get("descriptions", [])

        description_text = "No English description available."


        # Search through the available descriptions.
        for description in descriptions:

            # Use the English description when available.
            if description.get("lang") == "en":

                description_text = description.get(
                    "value",
                    description_text,
                )

                # Stop searching once we find English.
                break


        # --------------------------------------------------------
        # 3. Extract CVSS information.
        # --------------------------------------------------------

        # The NVD stores vulnerability metrics here.
        metrics = cve.get("metrics", {})


        # Safe default values.
        #
        # These prevent the script from crashing when a CVE
        # does not yet have CVSS information.
        cvss_score = None
        severity = "UNKNOWN"
        cvss_version = "UNKNOWN"


        # --------------------------------------------------------
        # First preference: CVSS version 3.1
        # --------------------------------------------------------

        cvss_v31 = metrics.get("cvssMetricV31", [])

        if cvss_v31:

            cvss_data = cvss_v31[0].get(
                "cvssData",
                {},
            )

            cvss_score = cvss_data.get("baseScore")

            severity = cvss_data.get(
                "baseSeverity",
                "UNKNOWN",
            )

            cvss_version = "3.1"


        # --------------------------------------------------------
        # Second preference: CVSS version 3.0
        # --------------------------------------------------------

        elif metrics.get("cvssMetricV30", []):

            cvss_v30 = metrics.get(
                "cvssMetricV30",
                [],
            )

            cvss_data = cvss_v30[0].get(
                "cvssData",
                {},
            )

            cvss_score = cvss_data.get("baseScore")

            severity = cvss_data.get(
                "baseSeverity",
                "UNKNOWN",
            )

            cvss_version = "3.0"


        # --------------------------------------------------------
        # Third preference: CVSS version 2.0
        # --------------------------------------------------------

        elif metrics.get("cvssMetricV2", []):

            cvss_v2 = metrics.get(
                "cvssMetricV2",
                [],
            )

            cvss_data = cvss_v2[0].get(
                "cvssData",
                {},
            )

            cvss_score = cvss_data.get("baseScore")

            cvss_version = "2.0"


            # CVSS version 2 does not always provide a severity label.
            #
            # Therefore, we calculate one from the score.
            if cvss_score is not None:

                if cvss_score >= 9.0:

                    severity = "CRITICAL"

                elif cvss_score >= 7.0:

                    severity = "HIGH"

                elif cvss_score >= 4.0:

                    severity = "MEDIUM"

                else:

                    severity = "LOW"


        # --------------------------------------------------------
        # 4. Calculate the initial CVSS-based priority.
        # --------------------------------------------------------

        initial_points, initial_label = calculate_priority(
            cvss_score,
        )


        # Explain the initial CVSS decision.
        priority_explanation = explain_priority(
            cvss_score,
            initial_points,
            initial_label,
        )


        # --------------------------------------------------------
        # 5. Check whether the CVE is in the KEV catalog.
        # --------------------------------------------------------

        # check_kev() returns TWO values:
        #
        #     1. True or False
        #        → Is this CVE known to be exploited?
        #
        #     2. The KEV record itself
        #        → The detailed information about the vulnerability.
        #
        # Python allows us to receive both values separately.
        is_known_exploited, kev_record = check_kev(
            cve_id,
            kev_lookup,
        )


        # --------------------------------------------------------
        # 6. Apply the KEV priority bonus.
        # --------------------------------------------------------

        final_points, kev_bonus = apply_kev_bonus(
            initial_points,
            is_known_exploited,
        )


        # --------------------------------------------------------
        # 7. Calculate the final priority label.
        # --------------------------------------------------------

        final_label = get_final_priority_label(
            final_points,
        )

        # --------------------------------------------------------
        # 8. Ask Gemini to analyze this REAL vulnerability.
        # --------------------------------------------------------
        #
        # The information below is no longer our hypothetical
        # CVE-EXAMPLE test data.
        #
        # These values come directly from the real vulnerability
        # currently being processed by this program.
        # --------------------------------------------------------

        ai_analysis = summarize_vulnerability(
            cve_id=cve_id,
            nvd_link=nvd_link,
            cvss_score=cvss_score,
            severity=severity,
            priority_label=final_label,
            priority_points=final_points,
            is_known_exploited=is_known_exploited,
            description=description_text,
        )
 

        # --------------------------------------------------------
        # 8. Display the result.
        # --------------------------------------------------------

        print("\n" + "=" * 70)

        print(f"CVE: {cve_id}")

        print(f"nvd_link: {nvd_link}")

        print(f"CVSS Version: {cvss_version}")

        print(f"CVSS Score: {cvss_score}")

        print(f"Severity: {severity}")

        print()


        # Display the original CVSS-based decision.
        print(f"INITIAL PRIORITY: {initial_label}")

        print(f"INITIAL PRIORITY POINTS: {initial_points}")

        print()


        # Display KEV status.
        print(
            f"KNOWN EXPLOITED: {is_known_exploited}"
        )

        print(f"KEV BONUS: +{kev_bonus}")

        print()


        # Display the final automation decision.
        print(f"FINAL PRIORITY: {final_label}")

        print(f"FINAL PRIORITY POINTS: {final_points}")

        print()


        print("WHY THIS INITIAL PRIORITY?")

        print(priority_explanation)

        print("-" * 70)


        # If the CVE exists in the KEV catalog,
        # display additional useful information.
        if is_known_exploited and kev_record:

            print("CISA KEV INFORMATION:")

            print(
                f"Vendor / Project: "
                f"{kev_record.get('vendorProject', 'Unknown')}"
            )

            print(
                f"Product: "
                f"{kev_record.get('product', 'Unknown')}"
            )

            print(
                f"Date Added: "
                f"{kev_record.get('dateAdded', 'Unknown')}"
            )

            print(
                f"Required Action: "
                f"{kev_record.get('requiredAction', 'Unknown')}"
            )

            print("-" * 70)


        print("Description:")

        print(description_text)



        # --------------------------------------------------------
        # Display the AI-generated cybersecurity analysis.
        # --------------------------------------------------------
        #
        # ai_analysis contains the text returned by Gemini.
        #
        # We already generated the analysis earlier with:
        #
        #     ai_analysis = summarize_vulnerability(...)
        #
        # Now we explicitly display that stored result.
        # --------------------------------------------------------

        print()

        print("-" * 70)

       
        print(f"AI SECURITY ANALYSIS:{ai_analysis}")

        print()

        

        print("=" * 70)


        # --------------------------------------------------------
        # Store this analyzed vulnerability.
        # --------------------------------------------------------

        # Instead of saving only text printed on the terminal,
        # we save structured information.
        #
        # This structure can later be used by:
        #
        #     report.py
        #     AI summarization
        #     email automation
        #     dashboards
        #     JSON storage
        analyzed_vulnerabilities.append(

            {
                "cve_id": cve_id,

                "nvd_link": nvd_link,

                "published": published,

                "cvss_version": cvss_version,

                "cvss_score": cvss_score,

                "severity": severity,

                "initial_label": initial_label,

                "initial_points": initial_points,

                "is_known_exploited": is_known_exploited,

                "kev_bonus": kev_bonus,

                "final_label": final_label,

                "final_points": final_points,

                "priority_explanation": (
                    priority_explanation
                ),

                "description": description_text,
                # Store the analysis produced by Gemini.
                # ----------------------------------------------------
                # i.e. Store the AI-generated analysis by appending it to analyzed_vulnerabilities
                # as part of the properties/elements of the loop.
                #
                # Without this field, the Gemini analysis exists only
                # temporarily in the ai_analysis variable and cannot
                # be used later by report.py or email automation.
                # ----------------------------------------------------
                "ai_analysis": ai_analysis,


                "kev_record": kev_record,
            }
        )
            # Return all analyzed vulnerabilities to the main program.
    return analyzed_vulnerabilities

# This section runs ONLY when this file is executed directly.
# ------------------------------------------------------------

# ------------------------------------------------------------
# MAIN PROGRAM
# ------------------------------------------------------------
def run_vulnerability_automation():
        
    print("\n[+] Starting cybersecurity threat automation...\n")


    # --------------------------------------------------------
    # STEP 1: Download the CISA KEV catalog ONCE.
    # --------------------------------------------------------

    print("[+] Acessing and Loading the Downloaded CISA KEV catalog...")

    # 1. Get KEV
    kev_catalog = get_kev_catalog()

    # 2. Create KEV lookup
    kev_lookup = create_kev_lookup(kev_catalog)

    # 3. Get recent NVD vulnerabilities
    recent_vulnerabilities = get_recent_vulnerabilities(
        hours=24,
        results_per_page=10,
    )

    # 4. Analyze them
    analyzed_vulnerabilities = display_vulnerabilities(
        recent_vulnerabilities,
        kev_lookup,
    )

    # 5. Create report
    report_path = create_report_file(
        analyzed_vulnerabilities,
    )

    # 6. Give the report path back to the orchestrator
    return report_path
# This section runs only when vulnerabilities.py is executed
# directly.
if __name__ == "__main__":
    run_vulnerability_automation()



    