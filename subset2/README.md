# Big-Vul Subset

Before building the Big-Vul Subset, download the required external resources:

1. **Big-Vul MSR Dataset**: Download the `MSR_data_cleaned.json` file from the official Big-Vul repository at [ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset). Alternatively, download directly from [this Google Drive link](https://drive.google.com/file/d/1deNsPfeh77h1SHjJURYOeyCR96JgxB_A/view?usp=sharing). Place it in the `subset2/` directory as `MSR_data_cleaned.json`.

2. **Extracted IDs Mapping**: The `itcFaultTypes/extracted_ids.json` file should already be included in the repository. This file contains the CWE IDs to filter Big-Vul samples by.

Once the dataset is in place, run the extraction and filtering pipeline in order:

```bash
uv run python subset2/extractData.py
uv run python subset2/subsetBuilder.py
```
