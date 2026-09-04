"""
email_sender.py

This module is responsible for delivering the cybersecurity
threat report through email.

Project pipeline:

    NVD
     ↓
    vulnerabilities.py
     ↓
    scorer.py
     ↓
    kev.py
     ↓
    summarizer.py (Gemini AI)
     ↓
    report.py
     ↓
    email_sender.py
     ↓
    Security analyst's inbox


The important idea here is:

    report.py CREATES the report.

    email_sender.py DELIVERS the report.
"""


# ------------------------------------------------------------
# IMPORT REQUIRED PYTHON MODULES
# ------------------------------------------------------------


# os allows us to read environment variables.
#
# We use environment variables so that sensitive information
# such as passwords does NOT need to be written directly
# inside this Python file.
import os


# smtplib allows Python to communicate with an SMTP server.
#
# SMTP means:
#
#     Simple Mail Transfer Protocol
#
# It is one of the standard technologies used to send email.
import smtplib


# EmailMessage helps us construct a properly formatted email.
from email.message import EmailMessage


# Path allows us to safely work with file paths.
from pathlib import Path


# ------------------------------------------------------------
# FUNCTION: SEND THREAT REPORT
# ------------------------------------------------------------

def send_threat_report(report_path):
    """
    Send a cybersecurity threat report as an email attachment.

    Parameters:

        report_path:
            The location of the report created by report.py.

    Example:

        /home/uzochi/cyber-threat-automation/reports/
        threat_report_2026-08-28_10-57-34_UTC.txt


    Returns:

        bool:

            True
                Email was sent successfully.

            False
                Something went wrong.
    """


    # --------------------------------------------------------
    # 1. READ EMAIL SETTINGS FROM THE ENVIRONMENT
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Read email configuration from environment variables.
    #
    # These values are stored in ~/.bashrc rather than directly
    # inside this Python script.
    #
    # This helps prevent accidentally uploading credentials to
    # GitHub.
    # --------------------------------------------------------

    sender_email_address = os.getenv(
        "SENDER_EMAIL_ADDRESS"
    )

    receiver_email_address = os.getenv(
        "RECEIVER_EMAIL_ADDRESS"
    )

    app_password = os.getenv(
        "APP_PASSWORD"
    )


    # --------------------------------------------------------
    # Check that the sender email address exists.
    # --------------------------------------------------------

    if not sender_email_address:

        print(
            "[!] SENDER_EMAIL_ADDRESS was not found."
        )

        return False


    # --------------------------------------------------------
    # Check that the receiver email address exists.
    # --------------------------------------------------------

    if not receiver_email_address:

        print(
            "[!] RECEIVER_EMAIL_ADDRESS was not found."
        )

        return False


    # --------------------------------------------------------
    # Check that the App Password exists.
    # --------------------------------------------------------
    #
    # An empty string:
    #
    #     ""
    #
    # behaves as False in Python.
    #
    # Therefore this check catches both:
    #
    #     Variable does not exist → None
    #
    # and:
    #
    #     Variable exists but is empty → ""
    # --------------------------------------------------------

    if not app_password:

        print(
            "[!] APP_PASSWORD was not found or is empty."
        )

        return False


    # --------------------------------------------------------
    # 3. CHECK THAT THE REPORT EXISTS
    # --------------------------------------------------------

    # Convert the report path into a Path object.
    report_file = Path(
        report_path
    )


    # Check whether the report exists.
    if not report_file.exists():

        print(
            "[!] Threat report file was not found."
        )

        print(
            f"[!] Expected location: {report_file}"
        )

        return False


    # --------------------------------------------------------
    # 4. CREATE THE EMAIL
    # --------------------------------------------------------

    print()

    print(
        "[+] Preparing cybersecurity threat report email..."
    )


    # Create an EmailMessage object.
    message = EmailMessage()


    # Set the sender.
    message["From"] = sender_email_address

    # Set the recipient.
    message["To"] = receiver_email_address


    
    
    # Set the subject line.
    message["Subject"] = (
        "Cybersecurity Threat Automation Report"
    )


    # --------------------------------------------------------
    # 5. CREATE THE EMAIL BODY
    # --------------------------------------------------------

    # This is the text that appears inside the email.
    #
    # The report itself will also be attached separately.
    message.set_content(
        """
    Hello,

    The Cybersecurity Threat Automation system has completed
    its latest vulnerability analysis.

    The attached report contains:

    - Recently published CVEs from NVD
    - CVSS severity information
    - Automation priority scoring
    - CISA Known Exploited Vulnerability checks
    - KEV priority adjustments
    - Gemini AI cybersecurity analysis
    - Recommended defensive considerations

    Please review the attached report.

    This message was generated automatically by the
    Cybersecurity Threat Automation project.
            """
    )


    # --------------------------------------------------------
    # 6. READ THE REPORT FILE
    # --------------------------------------------------------

    print(
        "[+] Reading the generated threat report..."
    )


    # Read the report as raw bytes.
    #
    # Attachments are normally handled as bytes rather than
    # ordinary Python strings.
    report_data = report_file.read_bytes()


    # --------------------------------------------------------
    # 7. ATTACH THE REPORT TO THE EMAIL
    # --------------------------------------------------------

    print(
        "[+] Attaching threat report..."
    )


    message.add_attachment(

        report_data,

        # Tell the email client that this is a generic file.
        maintype="application",

        # The subtype identifies it as plain text.
        subtype="octet-stream",

        # Use only the filename in the attachment.
        filename=report_file.name,
    )


    # --------------------------------------------------------
    # 8. CONNECT TO THE EMAIL SMTP SERVER
    # --------------------------------------------------------

    print(
        "[+] Connecting to email server..."
    )


    try:

        # Gmail SMTP server.
        smtp_server = "smtp.gmail.com"


        # Port 587 is commonly used for SMTP with STARTTLS.
        smtp_port = 587


        # Connect to the SMTP server.
        with smtplib.SMTP(
            smtp_server,
            smtp_port,
        ) as server:


            # Identify our application to the server.
            server.ehlo()


            # Upgrade the connection to an encrypted connection.
            #
            # TLS helps protect the connection between our
            # Python application and the email server.
            server.starttls()


            # Identify ourselves again after encryption starts.
            server.ehlo()


            print(
                "[+] Logging into email account..."
            )


            # Authenticate with the email provider.
            server.login(
                sender_email_address,
                app_password,
            )


            print(
                "[+] Sending threat report email..."
            )


            # Send the email.
            server.send_message(
                message,
            )


        # If we reach this point without an exception,
        # the email was sent successfully.
        print()

        print(
            "[+] Threat report email sent successfully!"
        )

        report_recipient = os.getenv(
            "RECEIVER_EMAIL_ADDRESS"
        )


        print(
            f"[+] Recipient: {report_recipient}"
        )


        return True


    except Exception as error:


        # Do not crash the entire cybersecurity automation.
        #
        # Instead, display the error and return False.
        print()

        print(
            "[!] Failed to send threat report email."
        )


        print(
            f"[!] Email error: {error}"
        )


        return False


# ------------------------------------------------------------
# TEST SECTION
# ------------------------------------------------------------

if __name__ == "__main__":

    print()

    print("=" * 70)

    print(
        "TESTING THE EMAIL DELIVERY MODULE"
    )

    print("=" * 70)


    # --------------------------------------------------------
    # Find the project directory.
    # --------------------------------------------------------

    # __file__ is the current Python file.
    #
    # This:
    #
    #     email_sender.py
    #
    # lives inside:
    #
    #     cyber-threat-automation/src/
    #
    # .parent.parent moves upward:
    #
    #     src
    #       ↑
    #     cyber-threat-automation
    project_directory = (
        Path(__file__).resolve().parent.parent
    )


    # --------------------------------------------------------
    # Locate the reports directory.
    # --------------------------------------------------------

    reports_directory = (
        project_directory / "reports"
    )


    # Find all threat report files.
    report_files = list(
        reports_directory.glob(
            "threat_report_*.txt"
        )
    )


    # Stop safely if no reports exist.
    if not report_files:

        print(
            "[!] No threat reports were found."
        )


    else:

        # Sort reports by modification time.
        #
        # reverse=True means newest first.
        report_files.sort(

            key=lambda file: file.stat().st_mtime,

            reverse=True,
        )


        # Select the newest report.
        latest_report = report_files[0]


        print()

        print(
            "[+] Latest report selected:"
        )


        print(
            latest_report
        )


        # ----------------------------------------------------
        # SEND THE REPORT
        # ----------------------------------------------------

        send_threat_report(
            latest_report
        )