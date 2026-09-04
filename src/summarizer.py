"""
summarizer.py

This module connects our Cyber Threat Automation project
to Google's Gemini Large Language Model (LLM).

Our project already performs several cybersecurity tasks:

    NVD API
        ↓
    vulnerabilities.py
        ↓
    Collect CVE information
        ↓
    scorer.py
        ↓
    Calculate cybersecurity priority
        ↓
    kev.py
        ↓
    Check whether the vulnerability is known to be exploited
        ↓
    summarizer.py
        ↓
    Ask Gemini AI to explain the vulnerability
        ↓
    Human-readable cybersecurity analysis


IMPORTANT IDEA:

The LLM does NOT replace our cybersecurity scoring system.

Instead:

    Our Python code
        ↓
    Collects factual information

    Our scorer.py
        ↓
    Makes deterministic priority decisions

    Gemini
        ↓
    Explains the information in human-readable language


This separation is important because we do not want the LLM
to invent CVSS scores or decide whether a CVE exists.

We provide the facts.

The AI helps us explain those facts.
"""


# ------------------------------------------------------------
# IMPORT REQUIRED PYTHON MODULES
# ------------------------------------------------------------


# os allows Python to communicate with the operating system.
#
# We use it to check whether GEMINI_API_KEY exists.
import os

# time allows Python to pause before retrying
# a temporarily unavailable API request.
import time

# Import Google's current Gemini Python SDK.
#
# This allows our Python program to communicate with
# Google's Gemini API.
from google import genai


# ------------------------------------------------------------
# FUNCTION: CHECK WHETHER THE GEMINI API KEY EXISTS
# ------------------------------------------------------------

def check_gemini_api_key():
    """
    Check whether GEMINI_API_KEY is available.

    The API key should NOT be written directly inside this
    Python file.

    Instead, it should exist in the Bash environment:

        export GEMINI_API_KEY="your-secret-key"

    Returns:

        True
            The API key was found.

        False
            The API key was not found.
    """


    # Ask the operating system:
    #
    # "Do you have an environment variable called
    # GEMINI_API_KEY?"
    gemini_api_key = os.getenv("GEMINI_API_KEY")


    # If the variable is empty or missing...
    if not gemini_api_key:

        print("[!] GEMINI_API_KEY was not found.")

        print()

        print(
            "[!] Make sure your API key is exported "
            "inside ~/.bashrc."
        )

        print()

        print(
            '    export GEMINI_API_KEY="YOUR_API_KEY"'
        )

        print()

        print(
            "[!] Then reload your Bash configuration:"
        )

        print()

        print("    source ~/.bashrc")

        return False


    # If the key exists, report success.
    print("[+] GEMINI_API_KEY was found.")

    return True


# ------------------------------------------------------------
# FUNCTION: CREATE THE GEMINI CLIENT
# ------------------------------------------------------------

def create_gemini_client():
    """
    Create and return a Gemini API client.

    The Google GenAI SDK automatically looks for
    GEMINI_API_KEY in the environment.

    Because we already stored the key in ~/.bashrc,
    we do NOT need to place the secret key inside
    this Python program.

    Returns:

        Gemini client object

    Or:

        None if the API key is missing.
    """


    # First make sure the API key exists.
    if not check_gemini_api_key():

        return None


    try:

        # Create a connection object that will communicate
        # with the Gemini API.
        #
        # The SDK automatically detects GEMINI_API_KEY.
        client = genai.Client()


        print("[+] Gemini client created successfully.")

        return client


    except Exception as error:

        # If something unexpected happens while creating
        # the client, report the error instead of crashing.
        print(
            "[!] Error while creating Gemini client:"
        )

        print(error)

        return None


# ------------------------------------------------------------
# FUNCTION: BUILD THE AI PROMPT
# ------------------------------------------------------------


def build_vulnerability_prompt(
    cve_id,
    nvd_link,
    cvss_score,
    severity,
    priority_label,
    priority_points,
    is_known_exploited,
    description,
):
    """
    Build the instructions that we will send to Gemini.

    A prompt is simply the information and instructions
    that we give to an LLM.

    We provide factual information collected by our
    cybersecurity automation.

    Gemini's job is to explain the information.

    The LLM does NOT make the original CVSS or priority
    decision. Those decisions have already been made by
    our Python automation.

    We are now asking Gemini to add human-readable analysis,
    a safe laboratory proof of concept, and an incident
    response statement.

    Parameters:

        cve_id:
            The CVE identification number.

        nvd_link:
            The NVD page associated with the CVE.

        cvss_score:
            The CVSS score supplied by NVD.

        severity:
            The severity supplied by NVD.

        priority_label:
            The priority calculated by scorer.py.

        priority_points:
            The points calculated by scorer.py.

        is_known_exploited:
            True if the CVE appears in the CISA KEV catalog.

        description:
            The vulnerability description collected from NVD.

    Returns:

        A formatted text prompt for Gemini.
    """


    # --------------------------------------------------------
    # Convert True/False into a clearer human-readable value.
    # --------------------------------------------------------

    if is_known_exploited:

        kev_status = "YES"

    else:

        kev_status = "NO"


    # --------------------------------------------------------
    # Build the prompt.
    # --------------------------------------------------------
    #
    # This is the most important part of this function.
    #
    # We are effectively giving Gemini a set of instructions:
    #
    #     "Here are the facts.
    #      Here is what our automation decided.
    #      Now explain them in this particular structure."
    #
    # Notice that we are NOT asking Gemini to calculate
    # the CVSS score or replace our scorer.py logic.
    # --------------------------------------------------------

    prompt = f"""
You are assisting a cybersecurity analyst in a defensive
cybersecurity threat-intelligence automation system.

Your task is to analyze the vulnerability information supplied
below and produce a clear, professional cybersecurity assessment.

IMPORTANT RULES
================================================

1. Use ONLY the vulnerability information provided below and
   reasonable defensive interpretation of that information.

2. Do NOT invent facts.

3. Do NOT invent a CVSS score, severity, affected product,
   affected version, exploitation status, or remediation detail.

4. Do NOT change the CVSS score or the automation priority.

5. Do NOT claim that a vulnerability is actively exploited
   unless the Known Exploited Vulnerability status says YES.

6. If information is missing, explicitly say that it is UNKNOWN
   or that a human analyst must verify it.

7. Clearly distinguish facts supplied by the vulnerability data
   from reasonable defensive recommendations.

8. Keep the overall analysis useful to cybersecurity analysts,
   system administrators, developers, and incident-response teams.

9. The Proof of Concept section must remain defensive and
   suitable for an AUTHORIZED LABORATORY ENVIRONMENT.

10. Do NOT provide destructive instructions, credential theft,
    persistence mechanisms, evasion techniques, malware,
    or instructions for attacking real-world systems.

11. If the supplied information is insufficient to construct
    a meaningful PoC, say so instead of inventing missing
    technical details.

12. When discussing remediation, distinguish between:
        - information explicitly supported by the CVE data
        - recommendations that should be verified by an analyst.

VULNERABILITY INFORMATION
================================================

CVE ID:
{cve_id}

NVD LINK:
{nvd_link}

CVSS SCORE:
{cvss_score}

SEVERITY:
{severity}

AUTOMATION PRIORITY:
{priority_label}

AUTOMATION PRIORITY POINTS:
{priority_points}

KNOWN EXPLOITED VULNERABILITY:
{kev_status}

NVD DESCRIPTION:
{description}

================================================


Please produce the following sections.

### 1. EXECUTIVE SUMMARY

Explain in clear language:

- What the vulnerability is.
- What type of security problem it represents.
- Who may potentially be affected.
- Whether it is currently listed as a known exploited
  vulnerability according to the supplied KEV status.

Do not add facts that are not supported by the supplied data.


### 2. POTENTIAL IMPACT

Explain what could potentially happen if the vulnerability
were successfully exploited.

Where appropriate, discuss possible effects such as:

- unauthorized access
- information disclosure
- modification of data
- authentication bypass
- code execution
- privilege escalation
- denial of service

Only discuss impacts that are reasonably supported by the
supplied vulnerability description.

Do not assume an impact that the source does not support.


### 3. WHO SHOULD CARE

Identify the people or teams that should investigate the issue.

For example:

- system administrators
- security analysts
- developers
- application owners
- network administrators
- incident-response teams

Explain why each relevant group may need to pay attention.


### 4. WHY THE AUTOMATION PRIORITIZED IT THIS WAY

Explain the priority decision using the values supplied by
our Python automation.

Include:

- CVSS score
- severity
- automation priority
- priority points
- KEV status

IMPORTANT:

Do NOT recalculate or replace the priority decision.

Explain the decision that our automation has already made.


### 5. DEFENSIVE ACTIONS

Provide practical defensive recommendations.

Where applicable, discuss:

1. Identifying affected systems.
2. Identifying affected software versions.
3. Checking official vendor advisories.
4. Applying available security updates.
5. Applying temporary mitigations where officially recommended.
6. Reviewing exposure.
7. Reviewing access controls.
8. Monitoring relevant logs.
9. Continuing to monitor the CVE and KEV status.

Clearly identify recommendations that require verification
by a human analyst.


### 6. ANALYST NOTE

Explain what a human cybersecurity analyst should verify.

Examples include:

- affected products
- affected versions
- whether the organization actually uses the affected software
- whether the vulnerable functionality is enabled
- network exposure
- authentication requirements
- available vendor patches
- evidence of exploitation
- relevant logs

Do not pretend that these facts are known if they were not
provided in the vulnerability information.


### 7. STEP-BY-STEP PROOF OF CONCEPT

Provide a DEFENSIVE, AUTHORIZED-LABORATORY proof of concept.

The purpose is to demonstrate and understand the vulnerability,
not to attack a real system.

Structure the PoC as follows where the supplied information
allows it:

STEP 1:
Describe how an analyst could establish an isolated test
environment containing an affected version.

STEP 2:
Describe the relevant vulnerable feature, component, endpoint,
function, or configuration identified by the CVE information.

STEP 3:
Describe the type of test input or condition that could be
used to demonstrate the vulnerability.

Do NOT invent an exact payload if the CVE information does not
provide enough information to construct one safely and accurately.

STEP 4:
Describe what the analyst should observe in the vulnerable
environment.

STEP 5:
Describe the expected security consequence if the vulnerability
is successfully demonstrated.

STEP 6:
Where information is available, describe how to repeat the
same test against a patched or unaffected version.

STEP 7:
Explain the difference between the vulnerable and patched
behavior.

IMPORTANT PoC SAFETY REQUIREMENTS:

- Assume the test is performed only on systems the analyst
  owns or is explicitly authorized to test.
- Keep the demonstration isolated from production systems.
- Do not provide credential-stealing instructions.
- Do not provide persistence mechanisms.
- Do not provide evasion techniques.
- Do not provide destructive actions.
- Do not provide malware.
- Do not provide instructions for attacking third-party systems.
- Do not invent technical details missing from the CVE description.

If the available information is insufficient for a meaningful
technical PoC, explicitly state:

"Insufficient information in the supplied vulnerability data
to construct a reliable technical PoC. A human analyst should
consult the official vendor advisory and reproduce the issue
only in an authorized laboratory environment."


### 8. INCIDENT RESPONSE STATEMENT

Write an incident-response statement explaining what a security
team should do if exploitation of this vulnerability is suspected.

Organize the response around the following stages:

IDENTIFICATION
- Identify potentially affected systems.
- Determine whether affected software and versions are present.
- Determine whether the vulnerable functionality is exposed.

CONTAINMENT
- Reduce exposure where appropriate.
- Restrict access to affected systems where appropriate.
- Apply vendor-recommended temporary mitigations when available.

INVESTIGATION
- Review application, authentication, system, and network logs
  where relevant.
- Look for activity consistent with the vulnerability.
- Preserve relevant evidence.
- Determine the scope of any suspected compromise.

REMEDIATION
- Apply the appropriate vendor security update when available.
- Remove or mitigate the vulnerable configuration where possible.
- Address any additional weaknesses discovered during investigation.

RECOVERY
- Restore affected services safely.
- Validate that the vulnerability has been remediated.
- Monitor systems after restoration.

MONITORING
- Continue monitoring for suspicious activity.
- Monitor NVD, vendor advisories, and CISA KEV status for changes.
- Reassess the organization's risk if new exploitation information
  becomes available.

IMPORTANT:

Do not state that exploitation actually occurred unless the
supplied information provides evidence of exploitation.

The incident-response section is a RECOMMENDATION for what a
security team should do if exploitation is suspected.


FINAL REQUIREMENT
================================================

Keep the entire response professional, technically useful,
well structured, and understandable to a cybersecurity analyst.

Do not invent missing facts.

Clearly distinguish:

FACTS FROM THE SUPPLIED CVE DATA

from

ANALYST RECOMMENDATIONS.

The final response must contain exactly these eight major sections:

1. EXECUTIVE SUMMARY
2. POTENTIAL IMPACT
3. WHO SHOULD CARE
4. WHY THE AUTOMATION PRIORITIZED IT THIS WAY
5. DEFENSIVE ACTIONS
6. ANALYST NOTE
7. STEP-BY-STEP PROOF OF CONCEPT
8. INCIDENT RESPONSE STATEMENT
"""


    # --------------------------------------------------------
    # Return the completed prompt to summarize_vulnerability().
    # --------------------------------------------------------
    #
    # Remember the journey:
    #
    # build_vulnerability_prompt()
    #             ↓
    #          returns
    #            prompt
    #             ↓
    # summarize_vulnerability()
    #             ↓
    # Gemini receives the prompt
    #             ↓
    # Gemini generates the analysis
    # --------------------------------------------------------

    

    # Return the completed prompt.
    return prompt


# ------------------------------------------------------------
# FUNCTION: ASK GEMINI TO ANALYZE A VULNERABILITY
# ------------------------------------------------------------

def summarize_vulnerability(
    cve_id,
    nvd_link,
    cvss_score,
    severity,
    priority_label,
    priority_points,
    is_known_exploited,
    description,
):
    """
    Send vulnerability information to Gemini and return
    a human-readable cybersecurity analysis.

    This function performs the following process:

        Vulnerability information
                ↓
        build_vulnerability_prompt()
                ↓
        Gemini API request
                ↓
        Gemini response
                ↓
        Return AI analysis

    Returns:

        str:
            The AI-generated analysis.

    If something goes wrong, an error message is returned.
    """


    print()

    print(
        f"[+] Preparing AI analysis for {cve_id}..."
    )


    # --------------------------------------------------------
    # 1. Create the Gemini client.
    # --------------------------------------------------------

    client = create_gemini_client()


    # If the client could not be created,
    # stop this function safely.
    if client is None:

        return (
            "AI analysis could not be generated because "
            "the Gemini client was not available."
        )


    # --------------------------------------------------------
    # 2. Build our cybersecurity prompt.
    # --------------------------------------------------------

    prompt = build_vulnerability_prompt(
        cve_id,
        nvd_link,
        cvss_score,
        severity,
        priority_label,
        priority_points,
        is_known_exploited,
        description,
    )


    print(
        "[+] Sending vulnerability information to Gemini..."
    )


    # --------------------------------------------------------
    # 3. Ask Gemini to generate an analysis.
    #
    # Gemini can occasionally return a temporary 503 error
    # when the service is experiencing high demand.
    #
    # Instead of immediately giving up, we will retry.
    #
    # This is called "exponential backoff".
    #
    # Example:
    #
    # Attempt 1 fails
    #     ↓
    # Wait 2 seconds
    #
    # Attempt 2 fails
    #     ↓
    # Wait 4 seconds
    #
    # Attempt 3 fails
    #     ↓
    # Wait 8 seconds
    #
    # Each wait becomes longer, giving the remote service
    # time to recover.
    # --------------------------------------------------------

    # Maximum number of times we will try the request.
    max_attempts = 4


    # The first waiting period.
    base_delay = 2


    # Start with no response.
    response = None


    # Store the last error in case all attempts fail.
    last_error = None


    # Try the Gemini request several times.
    for attempt in range(1, max_attempts + 1):

        try:

            print(
                f"[+] Gemini request attempt "
                f"{attempt}/{max_attempts}..."
            )


            # Send our cybersecurity prompt to Gemini.
            response = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt,
            )


            # If we reached this point, Gemini accepted
            # the request successfully.
            print(
                "[+] Gemini responded successfully."
            )


            # Stop the retry loop.
            break


        except Exception as error:

            # Remember the error.
            last_error = error


            print(
                f"[!] Gemini request failed: {error}"
            )


            # If this was our final attempt,
            # do not wait anymore.
            if attempt == max_attempts:

                break


            # Calculate how long to wait.
            #
            # Attempt 1:
            #
            #     2 * (2 ** 0) = 2 seconds
            #
            # Attempt 2:
            #
            #     2 * (2 ** 1) = 4 seconds
            #
            # Attempt 3:
            #
            #     2 * (2 ** 2) = 8 seconds
            #
            delay = base_delay * (
                2 ** (attempt - 1)
            )


            print(
                f"[+] Waiting {delay} seconds "
                "before trying again..."
            )


            # Pause Python temporarily.
            time.sleep(delay)


    # --------------------------------------------------------
    # 4. Check whether Gemini eventually succeeded.
    # --------------------------------------------------------

    if response is None:

        return (
            "AI analysis could not be generated after "
            f"{max_attempts} attempts. "
            f"Last API error: {last_error}"
        )


        # --------------------------------------------------------
    # 5. Extract the generated text.
    # --------------------------------------------------------

    # The API request succeeded, so extract Gemini's response.
    ai_analysis = response.text


    # Sometimes an API response may technically succeed
    # but not contain usable text.
    #
    # We check for that situation.
    if not ai_analysis:

        return (
            "Gemini returned a response, but no usable "
            "analysis text was available."
        )


    print(
        "[+] Gemini analysis generated successfully."
    )


    # Return the AI-generated cybersecurity analysis.
    return ai_analysis


# ------------------------------------------------------------
# TEST SECTION
# ------------------------------------------------------------
#
# This code runs ONLY when summarizer.py is executed directly.
#
# This allows us to test Gemini independently before
# connecting it to vulnerabilities.py and report.py.
# ------------------------------------------------------------

if __name__ == "__main__":


    print()

    print("=" * 70)

    print(
        "TESTING THE GEMINI CYBERSECURITY SUMMARIZER"
    )

    print("=" * 70)


    # --------------------------------------------------------
    # Create a SAFE TEST EXAMPLE.
    # --------------------------------------------------------
    #
    # These values are simply used to demonstrate that our
    # automation can send structured cybersecurity information
    # to Gemini.
    #
    # Later, these values will come automatically from:
    #
    # vulnerabilities.py
    # scorer.py
    # kev.py
    # --------------------------------------------------------

    test_cve_id = "CVE-EXAMPLE-2026-0001"

    test_nvd_link = "https://nist.../CVE-EXAMPLE-2026-0001"

    test_cvss_score = 8.8

    test_severity = "HIGH"

    test_priority_label = "HIGH"

    test_priority_points = 75

    test_is_known_exploited = False

    test_description = (
        "A hypothetical example vulnerability allows an "
        "authenticated attacker to execute unintended commands "
        "on an affected system."
    )


    # --------------------------------------------------------
    # Ask Gemini to analyze the example vulnerability.
    # --------------------------------------------------------

    analysis = summarize_vulnerability(
        cve_id=test_cve_id,
        nvd_link=test_nvd_link,
        cvss_score=test_cvss_score,
        severity=test_severity,
        priority_label=test_priority_label,
        priority_points=test_priority_points,
        is_known_exploited=test_is_known_exploited,
        description=test_description,
    )


    # --------------------------------------------------------
    # Display Gemini's analysis.
    # --------------------------------------------------------

    print()

    print("=" * 70)

    print("GEMINI AI SECURITY ANALYSIS")

    print("=" * 70)

    print()

    print(analysis)

    print()

    print("=" * 70)