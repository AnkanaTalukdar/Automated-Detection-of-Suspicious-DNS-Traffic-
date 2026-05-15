Technical Environmental Setup Report



##### **1. Virtualization Layer**



To ensure a secure and isolated environment for analyzing potentially malicious DNS strings, the project was deployed within a Virtual Machine (VM).



* **Hypervisor:** VirtualBox 7.x
* **Guest Operating System:** Ubuntu 24.04 LTS (64-bit)
* **Resources Allocated:** 4GB RAM, 25GB Storage, Bridged Network Adapter.
* **Clipboard Configuration:** Bidirectional Shared Clipboard enabled to facilitate code transfer between the host and guest OS.



##### **2. Directory Architecture**



A dedicated workspace was created to maintain organizational hygiene and prevent conflict with system-level files.



###### *Bash:*

*# Create the project root*

mkdir \~/dns\_project

cd \~/dns\_project



##### **3. Python Virtual Environment (venv)**

To prevent "Externally Managed Environment" errors and ensure dependency stability, a Python Virtual Environment was initialized. This isolates the project's libraries from the core Ubuntu operating system.



###### *Bash:*

*# Install the venv utility*

sudo apt install python3-venv -y



*# Create the environment*

python3 -m venv venv



*# Activation*

source venv/bin/activate



**Verification:** Successful activation is confirmed by the (*venv*) prefix appearing in the terminal prompt.



##### **4. Dependency Installation**



The system requires four key Python libraries to perform statistical analysis and data handling. These were installed using the pip package manager within the active virtual environment.



|Library|Purpose in Project|
|-|-|
|Pandas|Organizes DNS logs into structured data tables for reporting.|
|TLDExtract|Strips TLDs (like .com) to analyze the "core" domain string.|
|NumPy|Provides mathematical support for entropy calculations.|
|Scikit-learn(Optional)|Utilized for future Machine Learning classification.|



**Command:**



###### *Bash:*

pip install pandas tldextract numpy scikit-learn



##### **5. Development Tooling**



Due to the strict indentation requirements of Python, a Graphical User Interface (GUI) editor was selected over terminal-based editors to ensure code integrity.



* Primary Editor: Gedit (Ubuntu Text Editor)
* Execution Engine: Python 3.12+
* Logic Verification: Shannon Entropy algorithm validation.



##### **6. Setup Validation (Evidence)**



The following steps were taken to confirm the environment was ready for live analysis:



* Library Check: Running "*pip list*" to confirm all versions match project requirements.
* Network Check: Ensuring the VM can reach external DNS resolvers.
* Script Test: Executing a "Hello World" pandas script to verify the Dataframe rendering engine.













































