# ------------------------------------------------------------
# CYBER THREAT AUTOMATION ORCHESTRATOR
# ------------------------------------------------------------
#
# This script is the top-level controller of the project.
#
# Instead of manually running:
#
#     vulnerabilities.py
#
# and then manually running:
#
#     email_sender.py
#
# this script runs the entire cybersecurity automation
# pipeline from one command.
#
# ------------------------------------------------------------


# Import the main vulnerability automation function.
#
# This function:
#
#     - downloads the CISA KEV catalog
#     - collects recent vulnerabilities from NVD
#     - calculates priority
#     - checks KEV status
#     - sends vulnerability information to Gemini
#     - creates the cybersecurity threat report
#
from src.vulnerabilities import run_vulnerability_automation


# Import the email delivery function.
#
# IMPORTANT:
#
# We may need to adjust the exact function name below
# depending on what you named the email function inside
# email_sender.py.
#
from src.email_sender import send_threat_report


# ------------------------------------------------------------
# MAIN ORCHESTRATOR FUNCTION
# ------------------------------------------------------------
class theController():
    def run_cyber_threat_automation(self):
        """
        Run the complete cybersecurity threat automation system.

        The workflow is:

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

        print(
            "CYBER THREAT AUTOMATION SYSTEM"
        )

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

        print(
            "[+] STEP 1: Running vulnerability analysis..."
        )


        # vulnerabilities.py performs the analysis and
        # returns the location of the generated report.
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
        else: 

            


            print()

            print(
                "[+] Vulnerability analysis completed successfully."
            )



        # --------------------------------------------------------
        # STEP 3:
        # Send the report by email.
        # --------------------------------------------------------

        print()

        print(
            "[+] STEP 2: Sending threat report by email..."
        )


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

        return email_success()


    # ------------------------------------------------------------
    # PROGRAM ENTRY POINT
    # ------------------------------------------------------------

    # This section runs only when this file is executed directly.

    if __name__ == "__main__":

        run_cyber_threat_automation()