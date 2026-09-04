"""
report.py

This module is responsible for saving the results of our
cybersecurity threat automation into permanent report files.

The rest of the automation does the following:

    NVD
      ↓
    vulnerabilities.py
      ↓
    scorer.py
      ↓
    kev.py
      ↓
    Final vulnerability decisions
      ↓
    report.py
      ↓
    Timestamped report file

The goal of this file is simple:

    "Take the vulnerability decisions made by our automation
    and save them into a human-readable report."
"""


# pathlib provides a reliable way to work with folders and files.
from pathlib import Path


# datetime allows us to create timestamps for report filenames.
from datetime import datetime, timezone


# ------------------------------------------------------------
# REPORT FOLDER
# ------------------------------------------------------------

# __file__ represents the current file:
#
#     src/report.py
#
# .resolve() gives us the complete absolute path.
#
# .parent moves up one level:
#
#     src/
#
# .parent.parent moves up another level:
#
#     cyber-threat-automation/
#
PROJECT_FOLDER = Path(
    __file__
).resolve().parent.parent


# Create the path to our reports folder:
#
#     cyber-threat-automation/reports/
REPORTS_FOLDER = PROJECT_FOLDER / "reports"
def save_report(vulnerabilities):

    report_file.write(
        vulnerabilities["cve_id"]
    )

def create_report_file(vulnerabilities):
    """
    Create a timestamped cybersecurity threat report.

    Parameters:

        vulnerabilities (list):

            A list of dictionaries.

            Each dictionary represents one analyzed CVE.

    Returns:

        Path:

            The full path to the newly created report file.
    """


    # --------------------------------------------------------
    # 1. Make sure the reports folder exists.
    # --------------------------------------------------------

    # parents=True means Python may create missing parent folders.
    #
    # exist_ok=True means:
    #
    # "Do not crash if the folder already exists."
    REPORTS_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )


    # --------------------------------------------------------
    # 2. Create a timestamp.
    # --------------------------------------------------------

    # We use UTC because our security sources also use UTC.
    report_time = datetime.now(
        timezone.utc,
    )


    # Create a filename-safe timestamp.
    #
    # Example:
    #
    #     2026-08-26_12-45-30_UTC
    timestamp = report_time.strftime(
        "%Y-%m-%d_%H-%M-%S_UTC"
    )


    # Create the final report filename.
    #
    # Example:
    #
    # threat_report_2026-08-26_12-45-30_UTC.txt
    report_filename = (
        f"threat_report_{timestamp}.txt"
    )


    # Combine the reports folder and filename.
    report_path = (
        REPORTS_FOLDER / report_filename
    )


    # --------------------------------------------------------
    # 3. Open the file for writing.
    # --------------------------------------------------------

    # "w" means:
    #
    #     write a new file
    #
    # encoding="utf-8" allows the report to safely contain
    # normal Unicode characters.
    with open(
        report_path,
        "w",
        encoding="utf-8",
    ) as report_file:


        # ----------------------------------------------------
        # REPORT HEADER
        # ----------------------------------------------------

        report_file.write(
            "=" * 70 + "\n"
        )

        report_file.write(
            "CYBERSECURITY THREAT AUTOMATION REPORT\n"
        )

        report_file.write(
            "=" * 70 + "\n\n"
        )


        report_file.write(
            f"Report Generated (UTC): "
            f"{report_time.isoformat()}\n"
        )


        report_file.write(
            f"Vulnerabilities Analyzed: "
            f"{len(vulnerabilities)}\n\n"
        )


        # ----------------------------------------------------
        # WRITE EACH VULNERABILITY
        # ----------------------------------------------------

        for vulnerability in vulnerabilities:


            # Retrieve information safely from the dictionary.
            cve_id = vulnerability.get(
                "cve_id",
                "Unknown CVE",
            )

            published = vulnerability.get(
                "published",
                "Unknown",
            )

            cvss_version = vulnerability.get(
                "cvss_version",
                "UNKNOWN",
            )

            cvss_score = vulnerability.get(
                "cvss_score",
                None,
            )

            severity = vulnerability.get(
                "severity",
                "UNKNOWN",
            )

            initial_label = vulnerability.get(
                "initial_label",
                "UNKNOWN",
            )

            initial_points = vulnerability.get(
                "initial_points",
                0,
            )

            is_known_exploited = vulnerability.get(
                "is_known_exploited",
                False,
            )

            kev_bonus = vulnerability.get(
                "kev_bonus",
                0,
            )

            final_label = vulnerability.get(
                "final_label",
                "UNKNOWN",
            )

            final_points = vulnerability.get(
                "final_points",
                0,
            )

            explanation = vulnerability.get(
                "priority_explanation",
                "No explanation available.",
            )

            description = vulnerability.get(
                "description",
                "No description available.",
            )
            # ------------------------------------------------
            # GEMINI AI ANALYSIS
            # ------------------------------------------------

            # Retrieve the cybersecurity analysis generated
            # by the Gemini language model.
            #
            # If, for any reason, the AI analysis was not
            # available, use a safe message instead of
            # crashing the report generator.
            ai_analysis = vulnerability.get(
                "ai_analysis",
                "No AI analysis was available.",
            )

            nvd_link = vulnerability.get(
                "nvd_link",
                "Unavailable",
            )
            # ------------------------------------------------
            # GEMINI AI SECURITY ANALYSIS
            # ------------------------------------------------

            report_file.write(
                "AI SECURITY ANALYSIS:\n"
            )

            report_file.write(
                f"{ai_analysis}\n\n"
            )

            # End this CVE section.
            report_file.write(
                "=" * 70 + "\n\n"
            )


            # ------------------------------------------------
            # CVE HEADER
            # ------------------------------------------------

            report_file.write(
                "=" * 70 + "\n"
            )

            report_file.write(
                f"CVE: {cve_id}\n"
            )

            report_file.write(
                f"PUBLISHED BY NVD: {published}\n"
            )

            report_file.write(
                f"NVD VERIFICATION LINK: {nvd_link}\n"
            )

            report_file.write(
                "-" * 70 + "\n"
            )


            # ------------------------------------------------
            # CVSS INFORMATION
            # ------------------------------------------------

            report_file.write(
                f"CVSS Version: "
                f"{cvss_version}\n"
            )

            report_file.write(
                f"CVSS Score: "
                f"{cvss_score}\n"
            )

            report_file.write(
                f"Severity: "
                f"{severity}\n\n"
            )


            # ------------------------------------------------
            # INITIAL PRIORITY
            # ------------------------------------------------

            report_file.write(
                f"INITIAL PRIORITY: "
                f"{initial_label}\n"
            )

            report_file.write(
                f"INITIAL PRIORITY POINTS: "
                f"{initial_points}\n\n"
            )


            # ------------------------------------------------
            # KEV INFORMATION
            # ------------------------------------------------

            report_file.write(
                f"KNOWN EXPLOITED: "
                f"{is_known_exploited}\n"
            )

            report_file.write(
                f"KEV BONUS: "
                f"+{kev_bonus}\n\n"
            )


            # ------------------------------------------------
            # FINAL AUTOMATION DECISION
            # ------------------------------------------------

            report_file.write(
                f"FINAL PRIORITY: "
                f"{final_label}\n"
            )

            report_file.write(
                f"FINAL PRIORITY POINTS: "
                f"{final_points}\n\n"
            )


            # ------------------------------------------------
            # EXPLANATION
            # ------------------------------------------------

            report_file.write(
                "WHY THIS PRIORITY?\n"
            )

            report_file.write(
                f"{explanation}\n\n"
            )


            # ------------------------------------------------
            # OPTIONAL KEV DETAILS
            # ------------------------------------------------

            kev_record = vulnerability.get(
                "kev_record",
                None,
            )


            # Only write detailed KEV information if the CVE
            # actually exists in the KEV catalog.
            if is_known_exploited and kev_record:

                report_file.write(
                    "CISA KEV INFORMATION:\n"
                )

                report_file.write(
                    f"Vendor / Project: "
                    f"{kev_record.get('vendorProject', 'Unknown')}\n"
                )

                report_file.write(
                    f"Product: "
                    f"{kev_record.get('product', 'Unknown')}\n"
                )

                report_file.write(
                    f"Date Added: "
                    f"{kev_record.get('dateAdded', 'Unknown')}\n"
                )

                report_file.write(
                    f"Required Action: "
                    f"{kev_record.get('requiredAction', 'Unknown')}\n"
                )

                report_file.write(
                    "-" * 70 + "\n"
                )


            # ------------------------------------------------
            # DESCRIPTION
            # ------------------------------------------------

            report_file.write(
                "DESCRIPTION:\n"
            )

            report_file.write(
                f"{description}\n"
            )

            report_file.write(
                "=" * 70 + "\n\n"
            )

          
            report_file.write(
                "AI SECURITY ANALYSIS:\n"
            )

            report_file.write(
                f"{ai_analysis}\n"
            )

            report_file.write(
                "=" * 70 + "\n\n"
            )

    # Return the location of the report so the calling script
    # can tell us where it was saved.
    return report_path

    # ------------------------------------------------------------
# TEST SECTION
# ------------------------------------------------------------

# This runs only when report.py is executed directly.
if __name__ == "__main__":

    print(
        "\n[+] Testing the report generator...\n"
    )


    # Create one example vulnerability.
    test_vulnerabilities = [

        {
            "cve_id": "CVE-TEST-0001",

            "published": (
                "2026-08-26T10:00:00.000"
            ),

            "cvss_version": "3.1",

            "cvss_score": 9.8,

            "severity": "CRITICAL",

            "initial_label": "CRITICAL",

            "initial_points": 100,

            "is_known_exploited": True,

            "kev_bonus": 25,

            "final_label": "CRITICAL",

            "final_points": 100,

            "priority_explanation": (
                "This is a test explanation."
            ),
                        "ai_analysis": (
                "This is a demonstration of an AI-generated "
                "cybersecurity analysis. In the real automation, "
                "this text will be generated by Gemini."
            ),

            "description": (
                "This is a test vulnerability used to "
                "verify that report.py can create a report."
            ),

            "nvd_link": (
                "https://nvd.nist.gov/vuln/detail/"
                "CVE-TEST-0001"
            ),

            "kev_record": {

                "vendorProject": "Test Vendor",

                "product": "Test Product",

                "dateAdded": "2026-08-26",

                "requiredAction": (
                    "Apply the test security update."
                ),
            },
        }

    ]


    # Create the report.
    report_path = create_report_file(
        test_vulnerabilities,
    )


    print(
        "[+] Report created successfully:"
    )

    print(
        report_path
    )