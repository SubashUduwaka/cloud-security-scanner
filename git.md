---

### 3. Git Commands for v0.1

Run these commands one by one in your terminal from your project folder. This will create your first commit, tag it as `v0.1`, and push it to GitHub.

1. **Initialize the repository** (only run this once for the very first commit):
   
   ```bash
   git init -b main
   git remote add origin https://github.com/SubashUduwaka/cloud-security-scanner.git
   ```
2. **Add and commit the files:**
   
   ```bash
   git add .
   git commit -m "Initial commit: Add v0.1 S3 scanner script"
   ```
3. **Create the version tag:**
   
   ```bash
   git tag -a v0.1 -m "Version 0.1: Initial S3 Scanner"
   ```
4. **Push the commit and the tag to GitHub:**
   
   ```bash
   git push -u origin main
   git push origin v0.1
   ```

---

### 4. GitHub Release Notes for v0.1

After pushing, go to your GitHub repository, click on "Releases," and create a new release.

* **Tag:** Choose the `v0.1` tag you just pushed.
* **Release Title:** `Version 0.1: S3 Public Bucket Scanner`
* **Description (Changelog):**
  
  ```markdown
  This is the foundational release of the Cloud Security Scanner.
  ### ✨ New Features
  * **S3 Public Bucket Scanner:** Implemented a core script using `boto3` to connect to an AWS account, list all S3 buckets, and check for public accessibility through both Public Access Block settings and bucket policies.
  * **Command-Line Interface:** The tool runs as a simple Python script and prints findings directly to the console.
  ```
  
  You have now successfully documented and released the first version of your project! Let me know when you are ready to send the files for **Version 0.2**.
