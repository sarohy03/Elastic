# import json
# import openai
# import os
# import re
#
# from dotenv import load_dotenv
# from openai import OpenAI
#
# load_dotenv()
#
# OPENAI_ENDPOINT = os.environ.get('OPENAI_ENDPOINT')
# OPENAI_KEY = os.environ.get('OPENAI_KEY')
# OPENAI_DEPLOYMENT_NAME = os.environ.get('OPENAI_DEPLOYMENT_NAME')
# print(f'OPENAI_ENDPOINT: {OPENAI_ENDPOINT}')
#
# client = OpenAI(
#     base_url=OPENAI_ENDPOINT,
#     api_key=OPENAI_KEY,
# )
#
#
# def prompt_cves(products, cve_data):
#     print(f"Number of products: {len(products)}")
#     print(f"Number of CVEs in cve_data: {len(cve_data)}")
#
#     prompt = f"""
#             You are tasked with reviewing a list of products with specific versions and matching them against CVE records. Your output must be **consistent** each time, with no variations in results for identical input data.
#
#             ### Product List:
#             {products}
#
#             ### CVE Data:
#             {cve_data}
#
#             ### **Enhanced Instructions**:
#
#             1. **Flexible and Exact Matching**:
#                - **Exact Match**:
#                  - Include CVEs where the **product name** and **version** **exactly appear** in the CVE description.
#                - **Minor Version Variations**:
#                  - If a CVE mentions a version pattern like `2.47.x` and your product version is `2.47.0`, consider it a match.
#                  - Similarly, for `3.13.150.x` and `3.13.150.0`.
#                - **Inclusive Ranges**:
#                  - If a CVE mentions "prior to version X," include it only if your product version is **less than X**.
#                  - If a CVE specifies a range like "versions X to Y," include it only if your product version **falls within** that range.
#
#             2. **Product Name Variations and Synonyms**:
#                - **Standardize Names**:
#                  - Normalize product names to account for common synonyms and abbreviations.
#                    - Example:
#                      - `microsoft visual c++ 2019 x64 minimum runtime - 14` can be matched with `Microsoft Visual C++ 2019`, `Visual C++ 2019 Runtime`, etc.
#                      - `python 3 executables (64-bit)` can be matched with `Python 3.x`, `Python3 Executables`, etc.
#                - **Use Regex for Pattern Matching**:
#                  - Implement regex patterns to capture variations in product naming and version formatting.
#                    - Example Regex for Python 3 executables:
#                      - r'python\s*3(?:\.\d+){0, 3}\s*(?:executables|core interpreter|pip bootstrap|standard library)'
#
#             3. **Component and Module Matching**:
#                - **Specific Components**:
#                  - Ensure that CVEs targeting specific components or modules (e.g., `python 3 pip bootstrap`) are matched appropriately.
#                - **Granular Matching**:
#                  - If a CVE affects only a sub-component, ensure that the main product version still qualifies the CVE.
#
#             4. **Avoid Ambiguous Matches**:
#                - **Exclude Ambiguity**:
#                  - Do not include CVEs that mention ambiguous version patterns (e.g., "versions 2.x" without specific range details).
#                - **Clear Boundaries**:
#                  - Only include CVEs where the product version clearly falls within the affected range as per the CVE description.
#
#             5. **De-duplicate CVE IDs**:
#                - **Unique Listings**:
#                  - Ensure each CVE ID appears only once in the final output, even if it matches multiple products or is listed multiple times in the CVE data.
#
#             6. **Consistency and Repeatability**:
#                - **Deterministic Output**:
#                  - The matching process should yield the same results for identical inputs every time, regardless of minor differences in CVE descriptions.
#
#             7. **Final Output Format**:
#                - **List of CVE IDs**:
#                  - Return only the **CVE IDs** that match the products and versions.
#                - **JSON Array**:
#                  - Format the output as a JSON array for structured representation.
#             """
#
#     print("Sending request to OpenAI API...")
#     response = client.chat.completions.create(
#         model=OPENAI_DEPLOYMENT_NAME,
#         messages=[
#             # {"role": "system", "content": "You are a NVD DATABASE CRAWLER. Your response should strictly follow the"
#             #                               " structure: CVE : {'application': 'process_name','version':'process_version',"
#             #                               "'CVE': 'CVE-XXXX-number', 'Summary': 'Description of the CVE"
#             #                               " related to the exact version of the process.'}"},
#             {"role": "user", "content": prompt}
#         ],
#         temperature=1  # Make the output deterministic
#     )
#
#     print("Received response from OpenAI API")
#
#     # Extracting the content safely from the response
#     response_content = response.choices[0].message.content
#     print("Raw response from OpenAI API:", response)
#
#     # Try parsing the response as JSON
#     try:
#         print("Attempting to parse response as JSON...")
#         data = json.loads(response_content)
#         cve_ids = [item['CVE'] for item in data]
#         print("Successfully parsed response as JSON.")
#     except json.JSONDecodeError:
#         print("Failed to parse response as JSON. Fallback to regex.")
#         # If JSON parsing fails, fallback to regex
#         cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", response_content)
#
#     print(f"Number of extracted CVE IDs: {len(cve_ids)}")
#     print(f"Extracted CVE IDs: {cve_ids}")
#
#     return cve_ids
# import asyncio
# # import json
# # import os
# # import re
# # from dotenv import load_dotenv
# # from openai import OpenAI
# #
# # load_dotenv()
# #
# # OPENAI_ENDPOINT = os.environ.get('OPENAI_ENDPOINT')
# # OPENAI_KEY = os.environ.get('OPENAI_KEY')
# # OPENAI_DEPLOYMENT_NAME = os.environ.get('OPENAI_DEPLOYMENT_NAME')
# # print(f'OPENAI_ENDPOINT: {OPENAI_ENDPOINT}')
# #
# # client = OpenAI(
# #     base_url=OPENAI_ENDPOINT,
# #     api_key=OPENAI_KEY,
# # )
# #
# # # Mock data for products (apps) and CVEs
# # mock_apps = [
# #     {"app": "git", "version": "2.46.0"},
# #     {"app": "mozilla firefox 68.0 (x64 en-us)", "version": "68.0"},
# #     {"app": "python 3 standard library (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "microsoft visual c++ 2019 x64 minimum runtime - 14", "version": "14.29.30153"},
# #     {"app": "python 3 add to path (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "malwarebytes", "version": "5.1.7.121"},
# #     {"app": "python 3 executables (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "microsoft visual c++ 2019 x64 additional runtime - 14", "version": "14.29.30153"},
# #     {"app": "amazon ec2launch", "version": "2.0.1948.0"},
# #     {"app": "python 3 development libraries (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "python 3 core interpreter (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "node.js", "version": "20.16.0"},
# #     {"app": "python 3 test suite (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "python 3 tcl/tk support (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "python 3 pip bootstrap (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "nsclient++ (x64)", "version": "0.3.8.76"},
# #     {"app": "aws pv drivers", "version": "8.4.3"},
# #     {"app": "amazon ssm agent", "version": "3.3.551.0"},
# #     {"app": "disk pulse 10", "version": "10.0.12"},
# #     {"app": "npcap", "version": "1.79"},
# #     {"app": "vlc media player", "version": "3.0.17.4"},
# #     {"app": "microsoft edge", "version": "127.0.2651.105"},
# #     {"app": "microsoft visual c++ 2022 x86 minimum runtime - 14", "version": "14.38.33135"},
# #     {"app": "microsoft visual c++ 2022 x86 additional runtime - 14", "version": "14.38.33135"},
# #     {"app": "adobe reader xi", "version": "11.0.00"},
# #     {"app": "python launcher", "version": "3.12.5150.0"},
# #     {"app": "aws-cfn-bootstrap", "version": "2.0.29"},
# #     {"app": "python 3 documentation (64-bit)", "version": "3.12.5150.0"},
# #     {"app": "jinja2", "version": "2.10"},
# #     {"app": "microsoft visual studio code (user)", "version": "1.92.0"},
# #     {"app": "msdtc.exe", "version": "2001.12"},
# #     {"app": "node.exe", "version": "20.16"},
# #     {"app": "fontdrvhost.exe", "version": "10.0"},
# #     {"app": "rdpclip.exe", "version": "10.0"},
# #     {"app": "dwm.exe", "version": "10.0"},
# #     {"app": "cmd.exe", "version": "10.0"},
# #     {"app": "sihost.exe", "version": "10.0"},
# #     {"app": "nmap.exe", "version": "7.95"},
# #     {"app": "ApplicationFrameHost.exe", "version": "10.0"},
# #     {"app": "TextInputHost.exe", "version": "2010.1012"},
# #     {"app": "vds.exe", "version": "10.0"},
# #     {"app": "LiteAgent.exe", "version": "8.2"},
# #     {"app": "LogonUI.exe", "version": "10.0"},
# #     {"app": "ShellExperienceHost.exe", "version": "10.0"},
# #     {"app": "FreeSSHDService.exe", "version": "1.3.1"},
# #     {"app": "RuntimeBroker.exe", "version": "10.0"},
# #     {"app": "WmiPrvSE.exe", "version": "10.0"},
# #     {"app": "MsMpEng.exe", "version": "4.18"},
# #     {"app": "SearchApp.exe", "version": "10.0"},
# #     {"app": "electron.exe", "version": "26.6"},
# #     {"app": "dllhost.exe", "version": "10.0"},
# #     {"app": "armsvc.exe", "version": "1.7"},
# #     {"app": "SecurityHealthService.exe", "version": "10.0"},
# #     {"app": "NisSrv.exe", "version": "4.18"},
# #     {"app": "WUDFHost.exe", "version": "10.0"}
# # ]
# #
# # mock_cve_data = [
# #     {'id': 'CVE-2021-23632',
# #      'description': 'All versions of package git are vulnerable to Remote Code Execution (RCE) due to missing sanitization in the Git.git method, which allows execution of OS commands rather than just git commands. Steps to Reproduce 1. Create a file named exploit.js with the following content: js var Git = require("git").Git; var repo = new Git("repo-test"); var user_input = "version; date"; repo.git(user_input, function(err, result) { console.log(result); }) 2. In the same directory as exploit.js, run npm install git. 3. Run exploit.js: node exploit.js. You should see the outputs of both the git version and date command-lines. Note that the repo-test Git repository does not need to be present to make this PoC work.',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2023-29012',
# #      'description': 'Git for Windows is the Windows port of Git. Prior to version 2.40.1, any user of Git CMD who starts the command in an untrusted directory is impacted by an Uncontrolles Search Path Element vulnerability. Maliciously-placed `doskey.exe` would be executed silently upon running Git CMD. The problem has been patched in Git for Windows v2.40.1. As a workaround, avoid using Git CMD or, if using Git CMD, avoid starting it in an untrusted directory.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-24765',
# #      'description': 'Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users working on multi-user machines, where untrusted parties have write access to the same hard disk. Those untrusted parties could create the folder `C:\\.git`, which would be picked up by Git operations run supposedly outside a repository while searching for a Git directory. Git would then respect any config in said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are vulnerable: simply creating a new project would already read and respect the config specified in `C:\\.git\\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git` on all drives where Git commands are run, and remove read/write access from those folders as a workaround. Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user profile, e.g. `C:\\Users` if the user profile is located in `C:\\Users\\my-user-name`.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2012-6114',
# #      'description': 'The git-changelog utility in git-extras 1.7.0 allows local users to overwrite arbitrary files via a symlink attack on (1) /tmp/changelog or (2) /tmp/.git-effort.',
# #      'cvss_score': 5.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2023-49568',
# #      'description': 'A denial of service (DoS) vulnerability was discovered in go-git versions prior to v5.11. This vulnerability allows an attacker to perform denial of service attacks by providing specially crafted responses from a Git server which triggers resource exhaustion in go-git\xa0clients.\n\nApplications using only the in-memory filesystem supported by go-git\xa0are not affected by this vulnerability.\nThis is a go-git\xa0implementation issue and does not affect the upstream git\xa0cli.\n\n\n',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-11735',
# #      'description': 'Mozilla developers and community members reported memory safety bugs present in Firefox 68 and Firefox ESR 68. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Firefox < 69 and Firefox ESR < 68.1.',
# #      'cvss_score': 8.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-11740',
# #      'description': 'Mozilla developers and community members reported memory safety bugs present in Firefox 68, Firefox ESR 68, and Firefox 60.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1.',
# #      'cvss_score': 8.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-11710',
# #      'description': 'Mozilla developers and community members reported memory safety bugs present in Firefox 67. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Firefox < 68.',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2019-11734',
# #      'description': 'Mozilla developers and community members reported memory safety bugs present in Firefox 68. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Firefox < 69.',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2019-11709',
# #      'description': 'Mozilla developers and community members reported memory safety bugs present in Firefox 67 and Firefox ESR 60.7. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8.',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2019-0546',
# #      'description': 'A remote code execution vulnerability exists in Visual Studio when the C++ compiler improperly handles specific combinations of C++ constructs, aka "Visual Studio Remote Code Execution Vulnerability." This affects Microsoft Visual Studio.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-24765',
# #      'description': 'Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users working on multi-user machines, where untrusted parties have write access to the same hard disk. Those untrusted parties could create the folder `C:\\.git`, which would be picked up by Git operations run supposedly outside a repository while searching for a Git directory. Git would then respect any config in said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are vulnerable: simply creating a new project would already read and respect the config specified in `C:\\.git\\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git` on all drives where Git commands are run, and remove read/write access from those folders as a workaround. Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user profile, e.g. `C:\\Users` if the user profile is located in `C:\\Users\\my-user-name`.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2024-22410',
# #      'description': 'Creditcoin is a network that enables cross-blockchain credit transactions. The Windows binary of the Creditcoin node loads a suite of DLLs provided by Microsoft at startup. If a malicious user has access to overwrite the program files directory it is possible to replace these DLLs and execute arbitrary code. It is the view of the blockchain development team that the threat posed by a hypothetical binary planting attack is minimal and represents a low-security risk. The vulnerable DLL files are from the Windows networking subsystem, the Visual C++ runtime, and low-level cryptographic primitives. Collectively these dependencies are required for a large ecosystem of applications, ranging from enterprise-level security applications to game engines, and don’t represent a fundamental lack of security or oversight in the design and implementation of Creditcoin. The blockchain team takes the stance that running Creditcoin on Windows is officially unsupported and at best should be thought of as experimental.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2016-10717',
# #      'description': 'A vulnerability in the encryption and permission implementation of Malwarebytes Anti-Malware consumer version 2.2.1 and prior (fixed in 3.0.4) allows an attacker to take control of the whitelisting feature (exclusions.dat under %SYSTEMDRIVE%\\ProgramData) to permit execution of unauthorized applications including malware and malicious websites. Files blacklisted by Malwarebytes Malware Protect can be executed, and domains blacklisted by Malwarebytes Web Protect can be reached through HTTP.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-25150',
# #      'description': 'In Malwarebytes Binisoft Windows Firewall Control before 6.8.1.0, programs executed from the Tools tab can be used to escalate privileges.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-28641',
# #      'description': 'In Malwarebytes Free 4.1.0.56, a symbolic link may be used delete an arbitrary file on the system by exploiting the local quarantine system.',
# #      'cvss_score': 7.1, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-11507',
# #      'description': 'An Untrusted Search Path vulnerability in Malwarebytes AdwCleaner 8.0.3 could cause arbitrary code execution with SYSTEM privileges when a malicious DLL library is loaded.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-19929',
# #      'description': 'An Untrusted Search Path vulnerability in Malwarebytes AdwCleaner before 8.0.1 could cause arbitrary code execution with SYSTEM privileges when a malicious DLL library is loaded by the product.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-0546',
# #      'description': 'A remote code execution vulnerability exists in Visual Studio when the C++ compiler improperly handles specific combinations of C++ constructs, aka "Visual Studio Remote Code Execution Vulnerability." This affects Microsoft Visual Studio.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-24765',
# #      'description': 'Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users working on multi-user machines, where untrusted parties have write access to the same hard disk. Those untrusted parties could create the folder `C:\\.git`, which would be picked up by Git operations run supposedly outside a repository while searching for a Git directory. Git would then respect any config in said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are vulnerable: simply creating a new project would already read and respect the config specified in `C:\\.git\\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git` on all drives where Git commands are run, and remove read/write access from those folders as a workaround. Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user profile, e.g. `C:\\Users` if the user profile is located in `C:\\Users\\my-user-name`.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2024-22410',
# #      'description': 'Creditcoin is a network that enables cross-blockchain credit transactions. The Windows binary of the Creditcoin node loads a suite of DLLs provided by Microsoft at startup. If a malicious user has access to overwrite the program files directory it is possible to replace these DLLs and execute arbitrary code. It is the view of the blockchain development team that the threat posed by a hypothetical binary planting attack is minimal and represents a low-security risk. The vulnerable DLL files are from the Windows networking subsystem, the Visual C++ runtime, and low-level cryptographic primitives. Collectively these dependencies are required for a large ecosystem of applications, ranging from enterprise-level security applications to game engines, and don’t represent a fundamental lack of security or oversight in the design and implementation of Creditcoin. The blockchain team takes the stance that running Creditcoin on Windows is officially unsupported and at best should be thought of as experimental.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-2596',
# #      'description': 'Inefficient Regular Expression Complexity in GitHub repository node-fetch/node-fetch prior to 3.2.10.\n\n',
# #      'cvss_score': 5.9, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2017-16083',
# #      'description': 'node-simple-router is a minimalistic router for Node. node-simple-router is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing "../" in the URL.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2016-10618',
# #      'description': 'node-browser is a wrapper webdriver by nodejs. node-browser downloads resources over HTTP, which leaves it vulnerable to MITM attacks.',
# #      'cvss_score': 8.1, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2021-21421',
# #      'description': 'node-etsy-client is a NodeJs Etsy ReST API Client. Applications that are using node-etsy-client and reporting client error to the end user will offer api key value too This is fixed in node-etsy-client v0.3.0 and later.',
# #      'cvss_score': 6.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2021-21298',
# #      'description': 'Node-Red is a low-code programming for event-driven applications built using nodejs. Node-RED 1.2.7 and earlier has a vulnerability which allows arbitrary path traversal via the Projects API. If the Projects feature is enabled, a user with `projects.read` permission is able to access any file via the Projects API. The issue has been patched in Node-RED 1.2.8. The vulnerability applies only to the Projects feature which is not enabled by default in Node-RED. The primary workaround is not give untrusted users read access to the Node-RED editor.',
# #      'cvss_score': 6.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2024-7401',
# #      'description': 'Netskope was notified about a security gap in Netskope Client enrollment process where NSClient is using a static token “Orgkey” as authentication parameter. Since this is a static token, if leaked, cannot be rotated or revoked. A malicious actor can use this token to enroll NSClient from a customer’s tenant and impersonate a user.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-6384',
# #      'description': 'Unquoted Windows search path vulnerability in NSClient++ before 0.4.1.73 allows non-privileged local users to execute arbitrary code with elevated privileges on the system via a malicious program.exe executable in the %SYSTEMDRIVE% folder.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2021-44862',
# #      'description': 'Netskope client is impacted by a vulnerability where an authenticated, local attacker can view sensitive information stored in NSClient logs which should be restricted. The vulnerability exists because the sensitive information is not masked/scrubbed before writing in the logs. A malicious user can use the sensitive information to download data and impersonate another user.\n',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-29527',
# #      'description': 'Amazon AWS amazon-ssm-agent before 3.1.1208.0 creates a world-writable sudoers file, which allows local attackers to inject Sudo rules and escalate privileges to root. This occurs in certain situations involving a race condition.',
# #      'cvss_score': 7.0, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-11490',
# #      'description': 'An issue was discovered in Npcap 0.992. Sending a malformed .pcap file with the loopback adapter using either pcap_sendqueue_queue() or pcap_sendqueue_transmit() results in kernel pool corruption. This could lead to arbitrary code executing inside the Windows kernel and allow escalation of privileges.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-5459',
# #      'description': 'An Integer underflow in VLC Media Player versions < 3.0.7 leads to an out-of-band read.',
# #      'cvss_score': 7.1, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-14533',
# #      'description': 'The Control function of demux/asf/asf.c in VideoLAN VLC media player 3.0.7.1 has a use-after-free.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-14777',
# #      'description': 'The Control function of demux/mkv/mkv.cpp in VideoLAN VLC media player 3.0.7.1 has a use-after-free.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-5439',
# #      'description': 'A Buffer Overflow in VLC Media Player < 3.0.7 causes a crash which can possibly be further developed into a remote code execution exploit.',
# #      'cvss_score': 6.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2019-14778',
# #      'description': 'The mkv::virtual_segment_c::seek method of demux/mkv/virtual_segment.cpp in VideoLAN VLC media player 3.0.7.1 has a use-after-free.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-8278',
# #      'description': 'A spoofing vulnerability exists when Microsoft Edge improperly handles specific HTML content, aka "Microsoft Edge Spoofing Vulnerability." This affects Microsoft Edge.',
# #      'cvss_score': 6.1, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2018-8564',
# #      'description': 'A spoofing vulnerability exists when Microsoft Edge improperly handles specific HTML content, aka "Microsoft Edge Spoofing Vulnerability." This affects Microsoft Edge.',
# #      'cvss_score': 4.3, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2018-8425',
# #      'description': 'A spoofing vulnerability exists when Microsoft Edge improperly handles specific HTML content, aka "Microsoft Edge Spoofing Vulnerability." This affects Microsoft Edge.',
# #      'cvss_score': 4.3, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2019-0565',
# #      'description': 'A remote code execution vulnerability exists when Microsoft Edge improperly accesses objects in memory, aka "Microsoft Edge Memory Corruption Vulnerability." This affects Microsoft Edge.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-0566',
# #      'description': 'An elevation of privilege vulnerability exists in Microsoft Edge Browser Broker COM object, aka "Microsoft Edge Elevation of Privilege Vulnerability." This affects Microsoft Edge.',
# #      'cvss_score': 8.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-0546',
# #      'description': 'A remote code execution vulnerability exists in Visual Studio when the C++ compiler improperly handles specific combinations of C++ constructs, aka "Visual Studio Remote Code Execution Vulnerability." This affects Microsoft Visual Studio.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-24765',
# #      'description': 'Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users working on multi-user machines, where untrusted parties have write access to the same hard disk. Those untrusted parties could create the folder `C:\\.git`, which would be picked up by Git operations run supposedly outside a repository while searching for a Git directory. Git would then respect any config in said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are vulnerable: simply creating a new project would already read and respect the config specified in `C:\\.git\\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git` on all drives where Git commands are run, and remove read/write access from those folders as a workaround. Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user profile, e.g. `C:\\Users` if the user profile is located in `C:\\Users\\my-user-name`.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2024-22410',
# #      'description': 'Creditcoin is a network that enables cross-blockchain credit transactions. The Windows binary of the Creditcoin node loads a suite of DLLs provided by Microsoft at startup. If a malicious user has access to overwrite the program files directory it is possible to replace these DLLs and execute arbitrary code. It is the view of the blockchain development team that the threat posed by a hypothetical binary planting attack is minimal and represents a low-security risk. The vulnerable DLL files are from the Windows networking subsystem, the Visual C++ runtime, and low-level cryptographic primitives. Collectively these dependencies are required for a large ecosystem of applications, ranging from enterprise-level security applications to game engines, and don’t represent a fundamental lack of security or oversight in the design and implementation of Creditcoin. The blockchain team takes the stance that running Creditcoin on Windows is officially unsupported and at best should be thought of as experimental.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-0546',
# #      'description': 'A remote code execution vulnerability exists in Visual Studio when the C++ compiler improperly handles specific combinations of C++ constructs, aka "Visual Studio Remote Code Execution Vulnerability." This affects Microsoft Visual Studio.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-24765',
# #      'description': 'Git for Windows is a fork of Git containing Windows-specific patches. This vulnerability affects users working on multi-user machines, where untrusted parties have write access to the same hard disk. Those untrusted parties could create the folder `C:\\.git`, which would be picked up by Git operations run supposedly outside a repository while searching for a Git directory. Git would then respect any config in said Git directory. Git Bash users who set `GIT_PS1_SHOWDIRTYSTATE` are vulnerable as well. Users who installed posh-gitare vulnerable simply by starting a PowerShell. Users of IDEs such as Visual Studio are vulnerable: simply creating a new project would already read and respect the config specified in `C:\\.git\\config`. Users of the Microsoft fork of Git are vulnerable simply by starting a Git Bash. The problem has been patched in Git for Windows v2.35.2. Users unable to upgrade may create the folder `.git` on all drives where Git commands are run, and remove read/write access from those folders as a workaround. Alternatively, define or extend `GIT_CEILING_DIRECTORIES` to cover the _parent_ directory of the user profile, e.g. `C:\\Users` if the user profile is located in `C:\\Users\\my-user-name`.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2024-22410',
# #      'description': 'Creditcoin is a network that enables cross-blockchain credit transactions. The Windows binary of the Creditcoin node loads a suite of DLLs provided by Microsoft at startup. If a malicious user has access to overwrite the program files directory it is possible to replace these DLLs and execute arbitrary code. It is the view of the blockchain development team that the threat posed by a hypothetical binary planting attack is minimal and represents a low-security risk. The vulnerable DLL files are from the Windows networking subsystem, the Visual C++ runtime, and low-level cryptographic primitives. Collectively these dependencies are required for a large ecosystem of applications, ranging from enterprise-level security applications to game engines, and don’t represent a fundamental lack of security or oversight in the design and implementation of Creditcoin. The blockchain team takes the stance that running Creditcoin on Windows is officially unsupported and at best should be thought of as experimental.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2024-28823',
# #      'description': 'Amazon AWS aws-js-s3-explorer (aka AWS JavaScript S3 Explorer) 1.0.0 allows XSS via a crafted S3 bucket name to index.html.',
# #      'cvss_score': 'No score available', 'base_severity': 'No severity available'},
# #     {'id': 'CVE-2020-2311',
# #      'description': 'A missing permission check in Jenkins AWS Global Configuration Plugin 1.5 and earlier allows attackers with Overall/Read permission to replace the global AWS configuration.',
# #      'cvss_score': 4.3, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2023-30610',
# #      'description': "aws-sigv4 is a rust library for low level request signing in the aws cloud platform. The `aws_sigv4::SigningParams` struct had a derived `Debug` implementation. When debug-formatted, it would include a user's AWS access key, AWS secret key, and security token in plaintext. When TRACE-level logging is enabled for an SDK, `SigningParams` is printed, thereby revealing those credentials to anyone with access to logs. All users of the AWS SDK for Rust who enabled TRACE-level logging, either globally (e.g. `RUST_LOG=trace`), or for the `aws-sigv4` crate specifically are affected. This issue has been addressed in a set of new releases. Users are advised to upgrade. Users unable to upgrade should disable TRACE-level logging for AWS Rust SDK crates.\n",
# #      'cvss_score': 5.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2023-25956',
# #      'description': 'Generation of Error Message Containing Sensitive Information vulnerability in the Apache Airflow AWS Provider.\n\nThis issue affects Apache Airflow AWS Provider versions before 7.2.1.\n\n',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2021-40829',
# #      'description': 'Connections initialized by the AWS IoT Device SDK v2 for Java (versions prior to 1.4.2), Python (versions prior to 1.6.1), C++ (versions prior to 1.12.7) and Node.js (versions prior to 1.5.3) did not verify server certificate hostname during TLS handshake when overriding Certificate Authorities (CA) in their trust stores on MacOS. This issue has been addressed in aws-c-io submodule versions 0.10.5 onward. This issue affects: Amazon Web Services AWS IoT Device SDK v2 for Java versions prior to 1.4.2 on macOS. Amazon Web Services AWS IoT Device SDK v2 for Python versions prior to 1.6.1 on macOS. Amazon Web Services AWS IoT Device SDK v2 for C++ versions prior to 1.12.7 on macOS. Amazon Web Services AWS IoT Device SDK v2 for Node.js versions prior to 1.5.3 on macOS. Amazon Web Services AWS-C-IO 0.10.4 on macOS.',
# #      'cvss_score': 8.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-16935',
# #      'description': 'The documentation XML-RPC server in Python through 2.7.16, 3.x through 3.6.9, and 3.7.x through 3.7.4 has XSS via the server_title field. This occurs in Lib/DocXMLRPCServer.py in Python 2.x, and in Lib/xmlrpc/server.py in Python 3.x. If set_server_title is called with untrusted input, arbitrary JavaScript can be delivered to clients that visit the http URL for this server.',
# #      'cvss_score': 6.1, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2022-32151',
# #      'description': 'The httplib and urllib Python libraries that Splunk shipped with Splunk Enterprise did not validate certificates using the certificate authority (CA) certificate stores by default in Splunk Enterprise versions before 9.0 and Splunk Cloud Platform versions before 8.2.2203. Python 3 client libraries now verify server certificates by default and use the appropriate CA certificate stores for each library. Apps and add-ons that include their own HTTP libraries are not affected. For Splunk Enterprise, update to Splunk Enterprise version 9.0 and Configure TLS host name validation for Splunk-to-Splunk communications (https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/EnableTLSCertHostnameValidation) to enable the remediation.',
# #      'cvss_score': 9.1, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2021-28861',
# #      'description': 'Python 3.x through 3.10 has an open redirection vulnerability in lib/http/server.py due to no protection against multiple (/) at the beginning of URI path which may leads to information disclosure. NOTE: this is disputed by a third party because the http.server.html documentation page states "Warning: http.server is not recommended for production. It only implements basic security checks."',
# #      'cvss_score': 7.4, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-17514',
# #      'description': 'library/glob.html in the Python 2 and 3 documentation before 2016 has potentially misleading information about whether sorting occurs, as demonstrated by irreproducible cancer-research results. NOTE: the effects of this documentation cross application domains, and thus it is likely that security-relevant code elsewhere is affected. This issue is not a Python implementation bug, and there are no reports that NMR researchers were specifically relying on library/glob.html. In other words, because the older documentation stated "finds all the pathnames matching a specified pattern according to the rules used by the Unix shell," one might have incorrectly inferred that the sorting that occurs in a Unix shell also occurred for glob.glob. There is a workaround in newer versions of Willoughby nmr-data_compilation-p2.py and nmr-data_compilation-p3.py, which call sort() directly.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2023-40590',
# #      'description': " GitPython is a python library used to interact with Git repositories. When resolving a program, Python/Windows look for the current working directory, and after that the PATH environment. GitPython defaults to use the `git` command, if a user runs GitPython from a repo has a `git.exe` or `git` executable, that program will be run instead of the one in the user's `PATH`. This is more of a problem on how Python interacts with Windows systems, Linux and any other OS aren't affected by this. But probably people using GitPython usually run it from the CWD of a repo. An attacker can trick a user to download a repository with a malicious `git` executable, if the user runs/imports GitPython from that directory, it allows the attacker to run any arbitrary commands. There is no fix currently available for windows users, however there are a few mitigations. 1: Default to an absolute path for the git program on Windows, like `C:\\\\Program Files\\\\Git\\\\cmd\\\\git.EXE` (default git path installation). 2: Require users to set the `GIT_PYTHON_GIT_EXECUTABLE` environment variable on Windows systems. 3: Make this problem prominent in the documentation and advise users to never run GitPython from an untrusted repo, or set the `GIT_PYTHON_GIT_EXECUTABLE` env var to an absolute path. 4: Resolve the executable manually by only looking into the `PATH` environment variable.",
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2021-39286',
# #      'description': 'Webrecorder pywb before 2.6.0 allows XSS because it does not ensure that Jinja2 templates are autoescaped.',
# #      'cvss_score': 6.1, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2017-7481',
# #      'description': "Ansible before versions 2.3.1.0 and 2.4.0.0 fails to properly mark lookup-plugin results as unsafe. If an attacker could control the results of lookup() calls, they could inject Unicode strings to be parsed by the jinja2 templating system, resulting in code execution. By default, the jinja2 templating language is now marked as 'unsafe' and is not evaluated.",
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2022-45132',
# #      'description': 'In Linaro Automated Validation Architecture (LAVA) before 2022.11.1, remote code execution can be achieved through user-submitted Jinja2 template. The REST API endpoint for validating device configuration files in lava-server loads input as a Jinja2 template in a way that can be used to trigger remote code execution in the LAVA server.',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2022-34625',
# #      'description': 'Mealie1.0.0beta3 was discovered to contain a Server-Side Template Injection vulnerability, which allows attackers to execute arbitrary code via a crafted Jinja2 template.',
# #      'cvss_score': 7.2, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2023-25657',
# #      'description': 'Nautobot is a Network Source of Truth and Network Automation Platform. All users of Nautobot versions earlier than 1.5.7 are impacted by a remote code execution vulnerability. Nautobot did not properly sandbox Jinja2 template rendering. In Nautobot 1.5.7 has enabled sandboxed environments for the Jinja2 template engine used internally for template rendering for the following objects: `extras.ComputedField`, `extras.CustomLink`, `extras.ExportTemplate`, `extras.Secret`, `extras.Webhook`. While no active exploits of this vulnerability are known this change has been made as a preventative measure to protect against any potential remote code execution attacks utilizing maliciously crafted template code. This change forces the Jinja2 template engine to use a `SandboxedEnvironment` on all new installations of Nautobot. This addresses any potential unsafe code execution everywhere the helper function `nautobot.utilities.utils.render_jinja2` is called. Additionally, the documentation that had previously suggesting the direct use of `jinja2.Template` has been revised to suggest `render_jinja2`. Users are advised to upgrade to Nautobot 1.5.7 or newer. For users that are unable to upgrade to the latest release of Nautobot, you may add the following setting to your `nautobot_config.py` to apply the sandbox environment enforcement: `TEMPLATES[1]["OPTIONS"]["environment"] = "jinja2.sandbox.SandboxedEnvironment"` After applying this change, you must restart all Nautobot services, including any Celery worker processes. **Note:** *Nautobot specifies two template engines by default, the first being “django” for the Django built-in template engine, and the second being “jinja” for the Jinja2 template engine. This recommended setting will update the second item in the list of template engines, which is the Jinja2 engine.* For users that are unable to immediately update their configuration such as if a Nautobot service restart is too disruptive to operations, access to provide custom Jinja2 template values may be mitigated using permissions to restrict “change” (write) actions to the affected object types listed in the first section. **Note:** *This solution is intended to be stopgap until you can successfully update your `nautobot_config.py` or upgrade your Nautobot instance to apply the sandboxed environment enforcement.*',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2019-0546',
# #      'description': 'A remote code execution vulnerability exists in Visual Studio when the C++ compiler improperly handles specific combinations of C++ constructs, aka "Visual Studio Remote Code Execution Vulnerability." This affects Microsoft Visual Studio.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-8172',
# #      'description': 'A remote code execution vulnerability exists in Visual Studio software when the software does not check the source markup of a file for an unbuilt project, aka "Visual Studio Remote Code Execution Vulnerability." This affects Microsoft Visual Studio, Expression Blend 4.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-1147',
# #      'description': "A remote code execution vulnerability exists in .NET Framework, Microsoft SharePoint, and Visual Studio when the software fails to check the source markup of XML file input, aka '.NET Framework, SharePoint Server, and Visual Studio Remote Code Execution Vulnerability'.",
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-8232',
# #      'description': 'A Tampering vulnerability exists when Microsoft Macro Assembler improperly validates code, aka "Microsoft Macro Assembler Tampering Vulnerability." This affects Microsoft Visual Studio.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-2596',
# #      'description': 'Inefficient Regular Expression Complexity in GitHub repository node-fetch/node-fetch prior to 3.2.10.\n\n',
# #      'cvss_score': 5.9, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2017-16083',
# #      'description': 'node-simple-router is a minimalistic router for Node. node-simple-router is vulnerable to a directory traversal issue, giving an attacker access to the filesystem by placing "../" in the URL.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2016-10618',
# #      'description': 'node-browser is a wrapper webdriver by nodejs. node-browser downloads resources over HTTP, which leaves it vulnerable to MITM attacks.',
# #      'cvss_score': 8.1, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2021-21421',
# #      'description': 'node-etsy-client is a NodeJs Etsy ReST API Client. Applications that are using node-etsy-client and reporting client error to the end user will offer api key value too This is fixed in node-etsy-client v0.3.0 and later.',
# #      'cvss_score': 6.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2021-21298',
# #      'description': 'Node-Red is a low-code programming for event-driven applications built using nodejs. Node-RED 1.2.7 and earlier has a vulnerability which allows arbitrary path traversal via the Projects API. If the Projects feature is enabled, a user with `projects.read` permission is able to access any file via the Projects API. The issue has been patched in Node-RED 1.2.8. The vulnerability applies only to the Projects feature which is not enabled by default in Node-RED. The primary workaround is not give untrusted users read access to the Node-RED editor.',
# #      'cvss_score': 6.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2022-41096', 'description': 'Microsoft DWM Core Library Elevation of Privilege Vulnerability',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-21994', 'description': 'Windows DWM Core Library Elevation of Privilege Vulnerability',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2024-30008', 'description': 'Windows DWM Core Library Information Disclosure Vulnerability',
# #      'cvss_score': 5.5, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2022-24546', 'description': 'Windows DWM Core Library Elevation of Privilege Vulnerability',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2022-37970', 'description': 'Windows DWM Core Library Elevation of Privilege Vulnerability',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2023-29012',
# #      'description': 'Git for Windows is the Windows port of Git. Prior to version 2.40.1, any user of Git CMD who starts the command in an untrusted directory is impacted by an Uncontrolles Search Path Element vulnerability. Maliciously-placed `doskey.exe` would be executed silently upon running Git CMD. The problem has been patched in Git for Windows v2.40.1. As a workaround, avoid using Git CMD or, if using Git CMD, avoid starting it in an untrusted directory.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2019-13974', 'description': 'LayerBB 1.1.3 allows conversations.php/cmd/new CSRF.', 'cvss_score': 8.8,
# #      'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-20837',
# #      'description': 'include/admin/Menu/Ajax.php in Typesetter 5.1 has index.php/Admin/Menu/Ajax?cmd=AddHidden title XSS.',
# #      'cvss_score': 4.8, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2021-33655',
# #      'description': 'When sending malicious data to kernel by ioctl cmd FBIOPUT_VSCREENINFO, kernel will write memory out of bounds.',
# #      'cvss_score': 6.7, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2021-33656',
# #      'description': 'When setting font with malicious data by ioctl cmd PIO_FONT, kernel will write memory out of bounds.',
# #      'cvss_score': 6.8, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2021-3254',
# #      'description': 'Asus DSL-N14U-B1 1.1.2.3_805 allows remote attackers to cause a Denial of Service (DoS) via a TCP SYN scan using nmap.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-15840',
# #      'description': 'TP-Link TL-WR840N devices allow remote attackers to cause a denial of service (networking outage) via fragmented packets, as demonstrated by an "nmap -f" command.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-15173',
# #      'description': 'Nmap through 7.70, when the -sV option is used, allows remote attackers to cause a denial of service (stack consumption and application crash) via a crafted TCP-based service.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-7953',
# #      'description': 'An issue was discovered in OpServices OpMon 9.3.2. Without authentication, it is possible to read server files (e.g., /etc/passwd) due to the use of the nmap -iL (aka input file) option.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-8655',
# #      'description': 'An issue was discovered in EyesOfNetwork 5.3. The sudoers configuration is prone to a privilege escalation vulnerability, allowing the apache user to run arbitrary commands as root via a crafted NSE script for nmap 7.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-3234',
# #      'description': 'A vulnerability in the virtual console authentication of Cisco IOS Software for Cisco 809 and 829 Industrial Integrated Services Routers (Industrial ISRs) and Cisco 1000 Series Connected Grid Routers (CGR1000) could allow an authenticated but low-privileged, local attacker to log in to the Virtual Device Server (VDS) of an affected device by using a set of default credentials. The vulnerability is due to the presence of weak, hard-coded credentials. An attacker could exploit this vulnerability by authenticating to the targeted device and then connecting to VDS through the device’s virtual console by using the static credentials. A successful exploit could allow the attacker to access the Linux shell of VDS as the root user.',
# #      'cvss_score': 8.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-3210',
# #      'description': 'A vulnerability in the CLI parsers of Cisco IOS Software for Cisco 809 and 829 Industrial Integrated Services Routers (Industrial ISRs) and Cisco 1000 Series Connected Grid Routers (CGR1000) could allow an authenticated, local attacker to execute arbitrary shell commands on the Virtual Device Server (VDS) of an affected device. The attacker must have valid user credentials at privilege level 15. The vulnerability is due to insufficient validation of arguments that are passed to specific VDS-related CLI commands. An attacker could exploit this vulnerability by authenticating to the targeted device and including malicious input as the argument of an affected command. A successful exploit could allow the attacker to execute arbitrary commands in the context of the Linux shell of VDS with the privileges of the root user.',
# #      'cvss_score': 6.7, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2020-3205',
# #      'description': 'A vulnerability in the implementation of the inter-VM channel of Cisco IOS Software for Cisco 809 and 829 Industrial Integrated Services Routers (Industrial ISRs) and Cisco 1000 Series Connected Grid Routers (CGR1000) could allow an unauthenticated, adjacent attacker to execute arbitrary shell commands on the Virtual Device Server (VDS) of an affected device. The vulnerability is due to insufficient validation of signaling packets that are destined to VDS. An attacker could exploit this vulnerability by sending malicious packets to an affected device. A successful exploit could allow the attacker to execute arbitrary commands in the context of the Linux shell of VDS with the privileges of the root user. Because the device is designed on a hypervisor architecture, exploitation of a vulnerability that affects the inter-VM channel may lead to a complete system compromise. For more information about this vulnerability, see the Details section of this advisory.',
# #      'cvss_score': 8.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-0651',
# #      'description': 'Buffer overflow in the license management function of YOKOGAWA products (iDefine for ProSafe-RS R1.16.3 and earlier, STARDOM VDS R7.50 and earlier, STARDOM FCN/FCJ Simulator R4.20 and earlier, ASTPLANNER R15.01 and earlier, TriFellows V5.04 and earlier) allows remote attackers to stop the license management function or execute an arbitrary program via unspecified vectors.',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2020-3208',
# #      'description': 'A vulnerability in the image verification feature of Cisco IOS Software for Cisco 809 and 829 Industrial Integrated Services Routers (Industrial ISRs) could allow an authenticated, local attacker to boot a malicious software image on an affected device. The vulnerability is due to insufficient access restrictions on the area of code that manages the image verification feature. An attacker could exploit this vulnerability by first authenticating to the targeted device and then logging in to the Virtual Device Server (VDS) of an affected device. The attacker could then, from the VDS shell, disable Cisco IOS Software integrity (image) verification. A successful exploit could allow the attacker to boot a malicious Cisco IOS Software image on the targeted device. To exploit this vulnerability, the attacker must have valid user credentials at privilege level 15.',
# #      'cvss_score': 6.7, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2017-1000475',
# #      'description': 'FreeSSHd 1.3.1 version is vulnerable to an Unquoted Path Service allowing local users to launch processes with elevated privileges.',
# #      'cvss_score': 7.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2018-9853',
# #      'description': 'Insecure access control in freeSSHd version 1.3.1 allows attackers to obtain the privileges of the freesshd.exe process by leveraging the ability to login to an unprivileged account on the server.',
# #      'cvss_score': 9.8, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2024-0723',
# #      'description': 'A vulnerability was found in freeSSHd 1.0.9 on Windows. It has been classified as problematic. This affects an unknown part. The manipulation leads to denial of service. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-251547.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-25019',
# #      'description': 'jitsi-meet-electron (aka Jitsi Meet Electron) before 2.3.0 calls the Electron shell.openExternal function without verifying that the URL is for an http or https resource, in some circumstances.',
# #      'cvss_score': 7.5, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2016-10534',
# #      'description': 'electron-packager is a command line tool that packages Electron source code into `.app` and `.exe` packages. along with Electron. The `--strict-ssl` command line option in electron-packager >= 5.2.1 <= 6.0.0 || >=6.0.0 <= 6.0.2 defaults to false if not explicitly set to true. This could allow an attacker to perform a man in the middle attack.',
# #      'cvss_score': 5.9, 'base_severity': 'MEDIUM'},
# #     {'id': 'CVE-2018-1000118',
# #      'description': 'Github Electron version Electron 1.8.2-beta.4 and earlier contains a Command Injection vulnerability in Protocol Handler that can result in command execute. This attack appear to be exploitable via the victim opening an electron protocol handler in their browser. This vulnerability appears to have been fixed in Electron 1.8.2-beta.5. This issue is due to an incomplete fix for CVE-2018-1000006, specifically the black list used was not case insensitive allowing an attacker to potentially bypass it.',
# #      'cvss_score': 8.8, 'base_severity': 'HIGH'},
# #     {'id': 'CVE-2020-12079',
# #      'description': 'Beaker before 0.8.9 allows a sandbox escape, enabling system access and code execution. This occurs because Electron context isolation is not used, and therefore an attacker can conduct a prototype-pollution attack against the Electron internal messaging API.',
# #      'cvss_score': 10.0, 'base_severity': 'CRITICAL'},
# #     {'id': 'CVE-2020-15096',
# #      'description': 'In Electron before versions 6.1.1, 7.2.4, 8.2.4, and 9.0.0-beta21, there is a context isolation bypass, meaning that code running in the main world context in the renderer can reach into the isolated Electron context and perform privileged actions. Apps using "contextIsolation" are affected. There are no app-side workarounds, you must update your Electron version to be protected. This is fixed in versions 6.1.1, 7.2.4, 8.2.4, and 9.0.0-beta21.',
# #      'cvss_score': 6.8, 'base_severity': 'MEDIUM'}
# # ]
# #
# #
# # # def prompt_cves(products, cve_data):
# # #     print(f"Number of products: {len(products)}")
# # #     print(f"Number of CVEs in cve_data: {len(cve_data)}")
# # #
# # #     prompt = f"""
# # #             You are tasked with reviewing a list of products with specific versions and matching them against CVE records. Your output must be **consistent** each time, with no variations in results for identical input data.
# # #
# # #             ### Product List:
# # #             {products}
# # #
# # #             ### CVE Data:
# # #             {cve_data}
# # #
# # #             ### **Enhanced Matching Instructions**:
# # #
# # #             1. **Flexible and Exact Matching**:
# # #                - **Exact Match**:
# # #                  - Include CVEs where the **product name** and **version** **exactly appear** in the CVE description.
# # #                - **Minor Version Variations**:
# # #                  - If a CVE mentions a version pattern like `2.47.x` and your product version is `2.47.0`, consider it a match.
# # #                  - Similarly, for `3.13.150.x` and `3.13.150.0`.
# # #                - **Inclusive Ranges**:
# # #                  - If a CVE mentions "prior to version X," include it only if your product version is **less than X**.
# # #                  - If a CVE specifies a range like "versions X to Y," include it only if your product version **falls within** that range.
# # #
# # #             2. **Product Name Variations and Synonyms**:
# # #                - **Standardize Names**:
# # #                  - Normalize product names to account for common synonyms and abbreviations.
# # #                    - Example:
# # #                      - `microsoft visual c++ 2019 x64 minimum runtime - 14` can be matched with `Microsoft Visual C++ 2019`, `Visual C++ 2019 Runtime`, etc.
# # #                      - `python 3 executables (64-bit)` can be matched with `Python 3.x`, `Python3 Executables`, etc.
# # #                - **Use Regex for Pattern Matching**:
# # #                  - Implement regex patterns to capture variations in product naming and version formatting.
# # #                    - Example Regex for Python 3 executables:
# # #                      - `python\\s*3(?:\\.\\d+){0,3}\\s*(?:executables|core interpreter|pip bootstrap|standard library)`
# # #
# # #             3. **Component and Module Matching**:
# # #                - **Specific Components**:
# # #                  - Ensure that CVEs targeting specific components or modules (e.g., `python 3 pip bootstrap`) are matched appropriately.
# # #                - **Granular Matching**:
# # #                  - If a CVE affects only a sub-component, ensure that the main product version still qualifies the CVE.
# # #
# # #             4. **Avoid Ambiguous Matches**:
# # #                - **Exclude Ambiguity**:
# # #                  - Do not include CVEs that mention ambiguous version patterns (e.g., "versions 2.x" without specific range details).
# # #                - **Clear Boundaries**:
# # #                  - Only include CVEs where the product version clearly falls within the affected range as per the CVE description.
# # #
# # #             5. **De-duplicate CVE IDs**:
# # #                - **Unique Listings**:
# # #                  - Ensure each CVE ID appears only once in the final output, even if it matches multiple products or is listed multiple times in the CVE data.
# # #
# # #             6. **Consistency and Repeatability**:
# # #                - **Deterministic Output**:
# # #                  - The matching process should yield the same results for identical inputs every time, regardless of minor differences in CVE descriptions.
# # #
# # #             7. **Final Output Format**:
# # #                - **List of CVE IDs**:
# # #                  - Return only the **CVE IDs** that match the products and versions.
# # #                - **JSON Array**:
# # #                  - Format the output as a JSON array for structured representation.
# # #
# # #             ### **Instructions Summary**:
# # #
# # #             1. **Parse and Normalize Product Names**:
# # #                - Standardize product names to account for synonyms and variations.
# # #                - Use regex patterns to identify different naming conventions.
# # #
# # #             2. **Version Handling**:
# # #                - Match exact versions.
# # #                - Include minor and patch version variations.
# # #                - Handle inclusive version ranges based on CVE descriptions.
# # #
# # #             3. **Component Matching**:
# # #                - Identify and match CVEs targeting specific components or modules of a product.
# # #
# # #             4. **Exclude Ambiguous CVEs**:
# # #                - Do not include CVEs with unclear or vague version references.
# # #
# # #             5. **De-duplicate Results**:
# # #                - Ensure each CVE ID is listed only once.
# # #
# # #             6. **Consistent Formatting**:
# # #                - Return the final list as a JSON array containing only CVE IDs.
# # #             """
# # #
# # #     print("Sending request to OpenAI API...")
# # #     response = client.chat.completions.create(
# # #         model=OPENAI_DEPLOYMENT_NAME,
# # #         messages=[
# # #             {"role": "user", "content": prompt}
# # #         ],
# # #         temperature=1  # Make the output deterministic
# # #     )
# # #
# # #     print("Received response from OpenAI API")
# # #
# # #     # Extracting the content safely from the response
# # #     response_content = response.choices[0].message.content
# # #     print("Raw response from OpenAI API:", response)
# # #
# # #     # Try parsing the response as JSON
# # #     try:
# # #         print("Attempting to parse response as JSON...")
# # #         data = json.loads(response_content)
# # #         cve_ids = [item['CVE'] for item in data]
# # #         print("Successfully parsed response as JSON.")
# # #     except json.JSONDecodeError:
# # #         print("Failed to parse response as JSON. Fallback to regex.")
# # #         # If JSON parsing fails, fallback to regex
# # #         cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", response_content)
# # #
# # #     print(f"Number of extracted CVE IDs: {len(cve_ids)}")
# # #     print(f"Extracted CVE IDs: {cve_ids}")
# # #
# # #     return cve_ids
# # #
# # #
# # # seen_cve_ids = set()
# # # unique_cve_data = []
# # #
# # # # Loop through mock_cve_data and keep only unique records based on CVE ID
# # # for record in mock_cve_data:
# # #     if record['id'] not in seen_cve_ids:
# # #         unique_cve_data.append(record)
# # #         seen_cve_ids.add(record['id'])
# # #
# # # # Call the function at the end of the script with mock data
# # # cve_ids = prompt_cves(mock_apps, unique_cve_data)
# # # print(f"Final extracted CVE IDs: {cve_ids}")
#
import json
import os
import re
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

OPENAI_ENDPOINT = os.environ.get('OPENAI_ENDPOINT')
OPENAI_KEY = os.environ.get('OPENAI_KEY')
OPENAI_DEPLOYMENT_NAME = os.environ.get('OPENAI_DEPLOYMENT_NAME')
print(f'OPENAI_ENDPOINT: {OPENAI_ENDPOINT}')

client = OpenAI(
    base_url=OPENAI_ENDPOINT,
    api_key=OPENAI_KEY,
)


async def prompt_cves(products, cve_data):
    print(f"Number of products: {len(products)}")
    print(f"Number of CVEs in cve_data: {len(cve_data)}")

    prompt = f"""
            You are tasked with reviewing a list of products with specific versions and matching them against CVE records. Your output must be **consistent** each time, with no variations in results for identical input data.

            ### Product List:
            {products}

            ### CVE Data:
            {cve_data}

            ### **Enhanced Matching Instructions**:

            1. **Flexible and Exact Matching**:
               - **Exact Match**:
                 - Include CVEs where the **product name** and **version** **exactly appear** in the CVE description.
               - **Minor Version Variations**:
                 - If a CVE mentions a version pattern like `2.47.x` and your product version is `2.47.0`, consider it a match.
                 - Similarly, for `3.13.150.x` and `3.13.150.0`.
               - **Inclusive Ranges**:
                 - If a CVE mentions "prior to version X," include it only if your product version is **less than X**.
                 - If a CVE specifies a range like "versions X to Y," include it only if your product version **falls within** that range.

            2. **Product Name Variations and Synonyms**:
               - **Standardize Names**:
                 - Normalize product names to account for common synonyms and abbreviations.
                   - Example: 
                     - `microsoft visual c++ 2019 x64 minimum runtime - 14` can be matched with `Microsoft Visual C++ 2019`, `Visual C++ 2019 Runtime`, etc.
                     - `python 3 executables (64-bit)` can be matched with `Python 3.x`, `Python3 Executables`, etc.
               - **Use Regex for Pattern Matching**:
                 - Implement regex patterns to capture variations in product naming and version formatting.
                   - Example Regex for Python 3 executables:
                     - `python\\s*3(?:\\.\\d+){0, 3}\\s*(?:executables|core interpreter|pip bootstrap|standard library)`

            3. **Component and Module Matching**:
               - **Specific Components**:
                 - Ensure that CVEs targeting specific components or modules (e.g., `python 3 pip bootstrap`) are matched appropriately.
               - **Granular Matching**:
                 - If a CVE affects only a sub-component, ensure that the main product version still qualifies the CVE.

            4. **Avoid Ambiguous Matches**:
               - **Exclude Ambiguity**:
                 - Do not include CVEs that mention ambiguous version patterns (e.g., "versions 2.x" without specific range details).
               - **Clear Boundaries**:
                 - Only include CVEs where the product version clearly falls within the affected range as per the CVE description.

            5. **De-duplicate CVE IDs**:
               - **Unique Listings**:
                 - Ensure each CVE ID appears only once in the final output, even if it matches multiple products or is listed multiple times in the CVE data.

            6. **Consistency and Repeatability**:
               - **Deterministic Output**:
                 - The matching process should yield the same results for identical inputs every time, regardless of minor differences in CVE descriptions.

            7. **Final Output Format**:
               - **List of CVE IDs**:
                 - Return only the **CVE IDs** that match the products and versions.
               - **JSON Array**:
                 - Format the output as a JSON array for structured representation.

            ### **Instructions Summary**:

            1. **Parse and Normalize Product Names**:
               - Standardize product names to account for synonyms and variations.
               - Use regex patterns to identify different naming conventions.

            2. **Version Handling**:
               - Match exact versions.
               - Include minor and patch version variations.
               - Handle inclusive version ranges based on CVE descriptions.

            3. **Component Matching**:
               - Identify and match CVEs targeting specific components or modules of a product.

            4. **Exclude Ambiguous CVEs**:
               - Do not include CVEs with unclear or vague version references.

            5. **De-duplicate Results**:
               - Ensure each CVE ID is listed only once.

            6. **Consistent Formatting**:
               - Return the final list as a JSON array containing only CVE IDs.
            """

    while True:
        print("Sending request to OpenAI API...")
        response = await asyncio.to_thread(client.chat.completions.create,
                                           model=OPENAI_DEPLOYMENT_NAME,
                                           messages=[{"role": "user", "content": prompt}],
                                           temperature=1)

        print("Received response from OpenAI API")

        response_content = response.choices[0].message.content
        print("Raw response from OpenAI API:", response)

        try:
            print("Attempting to parse response as JSON...")
            data = json.loads(response_content)
            cve_ids = [item['CVE'] for item in data]
            print("Successfully parsed response as JSON.")
        except json.JSONDecodeError:
            print("Failed to parse response as JSON. Fallback to regex.")
            # If JSON parsing fails, fallback to regex
            cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", response_content)

        print(f"Number of extracted CVE IDs: {len(cve_ids)}")
        print(f"Extracted CVE IDs: {cve_ids}")

        if len(cve_ids) > 15:
            break

        print("Insufficient CVEs found, regenerating response...")

    return cve_ids
#
#
# async def main():
#
#     seen_cve_ids = set()
#     unique_cve_data = []
#
#     for record in mock_cve_data:
#         if record['id'] not in seen_cve_ids:
#             unique_cve_data.append(record)
#             seen_cve_ids.add(record['id'])
#
#     cve_ids = await prompt_cves(mock_apps, unique_cve_data)
#
#     print(f"Final extracted CVE IDs: {cve_ids}")
#
#
# if __name__ == "__main__":
#     asyncio.run(main())
