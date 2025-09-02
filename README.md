# SBOM for StatAnalysis

## How to run (RedHat v9.6)

1. Clone this repository ```git clone https://github.com/Tully9/AtlasStatAnalysis```
2. Insert ```cd AtlastStatAnalysis/``` into the terminal
3. Run the shell file ```sh startSBOM.sh```

```bash
git clone https://github.com/Tully9/AtlasStatAnalysis
cd AtlastStatAnalysis/
sh startSBOM.sh
```

## When activated, it will:
1. Create a temporarily virtual environment
2. Clone the StatAnalysis repository
3. Run the python script
4. Save the SBOM and Markdown file
5. Cleanup by deleting the cloned StatAnalysis repository and temporarily virtual environment