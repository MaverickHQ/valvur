"""Deliberately insecure sample. Planted for scanner tests.

These credentials are randomly generated and have never been valid anywhere.
They deliberately avoid AWS's published documentation keys (AKIAIOSFODNN7EXAMPLE
and friends), because gitleaks allowlists those — a fixture built from them is
unscannable by construction.
"""

AWS_ACCESS_KEY_ID = "AKIAV7Q2XR4TVBN6WLKJ"
AWS_SECRET_ACCESS_KEY = "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"
