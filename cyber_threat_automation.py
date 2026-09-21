# ------------------------------------------------------------
# CYBER THREAT AUTOMATION ORCHESTRATOR
# ------------------------------------------------------------
#
# This script is the top-level controller of the project.
#
# It does NOT modify vulnerabilities.py.
#
# It simply:
#
#     1. Runs vulnerability automation
#     2. Receives the generated report path
#     3. Sends the report by email
#     4. Displays the final result
#
# ------------------------------------------------------------


# ------------------------------------------------------------
# MAKE THE src DIRECTORY AVAILABLE TO PYTHON
# ------------------------------------------------------------
#
# vulnerabilities.py currently imports some modules like:
#
#     from report import save_report
#
# Because report.py is inside src/, we add src/ to Python's
# module search path here.
#
# This allows us to leave vulnerabilities.py unchanged.
# ------------------------------------------------------------

import sys
import os


SRC_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "src"
)


if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


# ------------------------------------------------------------
# IMPORT THE PROJECT FUNCTIONS
# ------------------------------------------------------------

from src.vulnerabilities import run_vulnerability_automation
from src.email_sender import send_threat_report


# ------------------------------------------------------------
# MAIN ORCHESTRATOR CLASS
# ------------------------------------------------------------

class theController:

    def run_cyber_threat_automation(self):
        """
        Run the complete cybersecurity threat automation system.

        Workflow:

            NVD vulnerabilities
                    ↓
            CVSS analysis
                    ↓
            Priority scoring
                    ↓
            CISA KEV checking
                    ↓
            Gemini AI analysis
                    ↓
            Threat report generation
                    ↓
            Email delivery
        """

        print()
        print("=" * 70)
        print("CYBER THREAT AUTOMATION SYSTEM")
        print("=" * 70)
        print()

        print(
            "[+] Starting the complete cybersecurity "
            "automation workflow..."
        )


        # --------------------------------------------------------
        # STEP 1:
        # Run vulnerability collection and analysis.
        # --------------------------------------------------------

        print()
        print("[+] STEP 1: Running vulnerability analysis...")


        report_path = run_vulnerability_automation()


        # --------------------------------------------------------
        # STEP 2:
        # Check whether a report was successfully created.
        # --------------------------------------------------------

        if not report_path:

            print()
            print(
                "[!] Automation stopped because no report "
                "was generated."
            )

            return False


        print()
        print(
            "[+] Vulnerability analysis completed successfully."
        )

        print(
            f"[+] Report created: {report_path}"
        )


        # --------------------------------------------------------
        # STEP 3:
        # Send the report by email.
        # --------------------------------------------------------

        print()
        print("[+] STEP 2: Sending threat report by email...")


        email_success = send_threat_report(
            report_path
        )


        # --------------------------------------------------------
        # STEP 4:
        # Display the final result.
        # --------------------------------------------------------

        print()
        print("=" * 70)


        if email_success:

            print(
                "[+] COMPLETE CYBER THREAT AUTOMATION "
                "FINISHED SUCCESSFULLY!"
            )

        else:

            print(
                "[!] Vulnerability analysis completed, "
                "but email delivery failed."
            )


        print("=" * 70)


        return email_success


# ------------------------------------------------------------
# PROGRAM ENTRY POINT
# ------------------------------------------------------------
#
# This runs only when this file is executed directly:
#
#     python3 cyber_threat_automation.py
#
# ------------------------------------------------------------

if __name__ == "__main__":

    controller = theController()

    controller.run_cyber_threat_automation()