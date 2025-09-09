---
name: Feature request
about: Suggest an idea for this project
title: ''
labels: ''
assignees: ''

---

name: ✨ Feature Request
description: Suggest an idea for this project.
title: "[Feature]: "
labels: ["enhancement"]
body:
  - type: markdown
    attributes:
      value: |
        Thank you for suggesting a new feature!

  - type: textarea
    id: related-problem
    attributes:
      label: Is your feature request related to a problem?
      description: A clear and concise description of what the problem is.
      placeholder: "I'm always frustrated when [...] because [...]. It would be great if the scanner could also check for [...]."
    validations:
      required: true

  - type: textarea
    id: solution
    attributes:
      label: Describe the solution you'd like
      description: A clear and concise description of what you want to happen.
      placeholder: "Add a new scan check that verifies if Azure Blob Storage containers are publicly accessible. It should show up in the dashboard just like the S3 and GCS checks."
    validations:
      required: true

  - type: textarea
    id: alternatives
    attributes:
      label: Describe alternatives you've considered
      description: A clear and concise description of any alternative solutions or features you've considered.
      placeholder: "Alternatively, a generic 'misconfigured services' section could be added where users can manually add checks."

  - type: checkboxes
    id: terms
    attributes:
      label: Code of Conduct
      description: By submitting this issue, you agree to follow our [Code of Conduct](https://github.com/SubashUduwaka/cloud-security-scanner/blob/main/CODE_OF_CONDUCT.md).
      options:
        - label: I agree to follow this project's Code of Conduct
          required: true
