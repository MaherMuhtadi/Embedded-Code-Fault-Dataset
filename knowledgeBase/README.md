# RAG Vector Knowledge Base

Before running the SEI CERT C Standard and CWE parsers, download the required external resources:

1. **SEI CERT C Coding Standard PDF**: Download the latest SEI CERT C Coding Standard PDF from [https://www.sei.cmu.edu/forms/secure-coding-form/](https://www.sei.cmu.edu/forms/secure-coding-form/). Place it in `knowledgeBase/certData/SEI_CERT_C_Coding_Standard_2016_Edition.pdf` (or update the path in `certParser.py` if using a different version).

2. **SEI CERT C Code Samples**: Download and extract the [dyesmar/sei-cert-ccs-samples](https://github.com/dyesmar/sei-cert-ccs-samples) repository into the `knowledgeBase/certData/sei-cert-ccs-samples/` directory.

3. **CWE XML Data**: The `knowledgeBase/cweData/cwec_v4.18.xml` file should already be included in this repository. If you need a different CWE version, download it from [https://cwe.mitre.org/data/](https://cwe.mitre.org/data/).

Once these resources are in place, run the parsers in order:

```bash
uv run python knowledgeBase/cweParser.py
uv run python knowledgeBase/certParser.py
uv run python knowledgeBase/kbBuilder.py
```
