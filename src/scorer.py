"""
scorer.py

This module is responsible for prioritizing vulnerabilities.

The vulnerability collector retrieves CVE information from NVD.

This module answers a different question:

    "How urgently should we pay attention to this vulnerability?"

For the first version, we use the CVSS base score.

Later, this module can become more intelligent by considering:

    - Known Exploited Vulnerability (KEV) status
    - Attack vector
    - Privileges required
    - User interaction
    - Exploit availability
    - Affected products
"""


def calculate_priority(cvss_score):
    """
    Convert a CVSS score into a priority score and label.

    Parameters:
        cvss_score (float or None):
            The CVSS base score.

    Returns:
        tuple:
            (
                priority_points,
                priority_label
            )

    Example:

        calculate_priority(8.8)

    Returns:

        (75, "HIGH")
    """


    # ------------------------------------------------------------
    # 1. Handle missing CVSS information.
    # ------------------------------------------------------------

    # Some newly published CVEs may not yet have a score.
    #
    # We should not crash simply because NVD has not completed
    # its analysis.
    if cvss_score is None:

        return 0, "UNKNOWN"


    # ------------------------------------------------------------
    # 2. CRITICAL vulnerabilities.
    # ------------------------------------------------------------

    # CVSS scores from 9.0 up to 10.0 are treated as CRITICAL.
    if cvss_score >= 9.0:

        return 100, "CRITICAL"


    # ------------------------------------------------------------
    # 3. HIGH vulnerabilities.
    # ------------------------------------------------------------

    # Scores from 7.0 up to 8.9 are treated as HIGH.
    elif cvss_score >= 7.0:

        return 75, "HIGH"


    # ------------------------------------------------------------
    # 4. MEDIUM vulnerabilities.
    # ------------------------------------------------------------

    # Scores from 4.0 up to 6.9 are treated as MEDIUM.
    elif cvss_score >= 4.0:

        return 50, "MEDIUM"


    # ------------------------------------------------------------
    # 5. LOW vulnerabilities.
    # ------------------------------------------------------------

    # Scores below 4.0 are treated as LOW.
    else:

        return 25, "LOW"


def explain_priority(cvss_score, priority_points, priority_label):
    """
    Create a human-readable explanation of the priority decision.

    This is useful because our automation should not simply say:

        HIGH

    It should be able to explain:

        WHY it made that decision.

    Parameters:
        cvss_score:
            The vulnerability's CVSS base score.

        priority_points:
            The numeric priority assigned by calculate_priority().

        priority_label:
            The text label assigned by calculate_priority().

    Returns:
        str:
            A readable explanation.
    """


    # Handle CVEs that do not yet have a CVSS score.
    if cvss_score is None:

        return (
            "Priority is UNKNOWN because NVD has not yet "
            "provided a usable CVSS score."
        )


    # Explain the decision using the actual values.
    return (
        f"The CVSS score is {cvss_score}, "
        f"so the automation assigned {priority_points} "
        f"priority points and classified this vulnerability "
        f"as {priority_label}."
    )


# ------------------------------------------------------------
# TEST SECTION
# ------------------------------------------------------------

# This code runs only when scorer.py is executed directly.
#
# It allows us to test the scoring logic by itself before
# connecting it to the NVD vulnerability collector.
if __name__ == "__main__":

    print("\n[+] Testing vulnerability priority scoring...\n")


    # These are example scores representing different levels
    # of vulnerability severity.
    test_scores = [

        9.8,       # Expected: CRITICAL
        8.8,       # Expected: HIGH
        6.5,       # Expected: MEDIUM
        3.2,       # Expected: LOW
        None,      # Expected: UNKNOWN

    ]


    # Test every example score.
    for score in test_scores:

        # Ask our scoring function to make a decision.
        points, label = calculate_priority(score)


        # Ask our explanation function to explain that decision.
        explanation = explain_priority(
            score,
            points,
            label,
        )


        # Display the results.
        print("=" * 70)

        print(f"CVSS Score: {score}")

        print(f"Priority Points: {points}")

        print(f"Priority Label: {label}")

        print()

        print("Explanation:")

        print(explanation)

        print("=" * 70)

        # ------------------------------------------------------------
# KEV PRIORITY ADJUSTMENT
# ------------------------------------------------------------

def apply_kev_bonus(priority_points, is_known_exploited):
    """
    Adjust the vulnerability priority when the vulnerability
    is known to have been exploited in the real world.

    Parameters:

        priority_points (int):
            The original priority points calculated from CVSS.

        is_known_exploited (bool):
            True means the CVE was found in the CISA KEV catalog.
            False means it was not found.

    Returns:

        tuple:

            (
                adjusted_points,
                kev_bonus
            )
    """


    # Start by assuming that there is no KEV bonus.
    kev_bonus = 0


    # If the vulnerability is known to be exploited,
    # increase its priority.
    if is_known_exploited:

        # Add 25 points because real-world exploitation
        # makes the vulnerability more urgent.
        kev_bonus = 25


    # Add the KEV bonus to the original priority.
    adjusted_points = priority_points + kev_bonus


    # Our priority scale currently has a maximum of 100.
    #
    # min() chooses the smaller value.
    #
    # Example:
    #
    #     min(125, 100)
    #
    # becomes:
    #
    #     100
    adjusted_points = min(
        adjusted_points,
        100,
    )


    return adjusted_points, kev_bonus


def get_final_priority_label(priority_points):
    """
    Convert the final priority points into a readable label.

    Returns one of:

        UNKNOWN
        LOW
        MEDIUM
        HIGH
        CRITICAL
    """


    # No usable score.
    if priority_points == 0:

        return "UNKNOWN"


    # Maximum priority.
    if priority_points >= 100:

        return "CRITICAL"


    # High priority.
    elif priority_points >= 75:

        return "HIGH"


    # Medium priority.
    elif priority_points >= 50:

        return "MEDIUM"


    # Anything below 50 is LOW.
    else:

        return "LOW"


        # ------------------------------------------------------------
# KEV TEST SECTION
# ------------------------------------------------------------

# This is another test block.
#
# Python runs it only when scorer.py itself is executed directly.
if __name__ == "__main__":

    print("\n[+] Testing KEV priority adjustment...\n")


    # Imagine that CVSS scoring gave this vulnerability
    # 75 priority points.
    original_points = 75


    # Pretend that kev.py found this CVE inside the
    # CISA Known Exploited Vulnerabilities catalog.
    known_exploited = True


    # Apply our KEV bonus.
    final_points, kev_bonus = apply_kev_bonus(
        original_points,
        known_exploited,
    )


    # Translate the final numeric score into a label.
    final_label = get_final_priority_label(
        final_points
    )


    # Display the decision.
    print(f"Original Priority Points: {original_points}")

    print(f"Known Exploited: {known_exploited}")

    print(f"KEV Bonus: +{kev_bonus}")

    print(f"Final Priority Points: {final_points}")

    print(f"Final Priority Label: {final_label}")