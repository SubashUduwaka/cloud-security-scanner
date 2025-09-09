---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

name: 🐞 Bug Report
description: Create a report to help us improve the Aegis scanner.
title: "[Bug]: "
labels: ["bug", "triage"]
body:
  - type: markdown
    attributes:
      value: |
        Thank you for taking the time to fill out this bug report! Please be as detailed as possible.

  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: A clear and concise description of what the bug is.
      placeholder: "When I tried to scan my GCP project, the application crashed and showed a '500 Internal Server Error' page."
    validations:
      required: true

  - type: textarea
    id: steps-to-reproduce
    attributes:
      label: Steps to Reproduce
      description: "How can we reproduce the issue? Please be specific."
      placeholder: |
        1. Go to 'Settings'
        2. Click on 'Add New Profile' for GCP
        3. Paste a valid GCP Service Account JSON key
        4. Go to 'Dashboard', select the GCP profile, and click 'Run Scan'
        5. The scan fails immediately.
    validations:
      required: true

  - type: textarea
    id: expected-behavior
    attributes:
      label: Expected Behavior
      description: What did you expect to happen?
      placeholder: "I expected the scan to start running and show progress in the console."
    validations:
      required: true

  - type: dropdown
    id: os
    attributes:
      label: Operating System
      description: What operating system are you using?
      options:
        - Windows 11
        - Windows 10
        - macOS
        - Linux
    validations:
      required: true

  - type: dropdown
    id: browser
    attributes:
      label: Browser
      description: Which browser did you experience the issue in?
      options:
        - Google Chrome
        - Mozilla Firefox
        - Microsoft Edge
        - Safari
        - Other
    validations:
      required: true

  - type: textarea
    id: logs
    attributes:
      label: Relevant Log Output
      description: |
        Please copy and paste any relevant log output from the terminal or from the application's log file. This is very important!
        The log file can be found at `%LOCALAPPDATA%\AegisScanner\aegis_scanner_debug.log` on Windows.
      render: shell
