#!/bin/bash

# Master test script to run all tests

# Run bash tests
echo "Running bash tests..."
for test_script in $(find tests/bash -name "*.sh"); do
    if [[ "$test_script" == *"sqli_test.sh"* ]]; then
        echo "Skipping $test_script, needs a URL"
        continue
    fi
    if [[ "$test_script" == *"test_alienvault.sh"* ]]; then
        echo "Running $test_script with bats"
        ./scripts/recon/tests/lib/bats-core/bin/bats "$test_script"
    else
        echo "Running $test_script"
        bash "$test_script"
    fi
done

# Run python tests
echo "Running python tests..."
export PYTHONPATH=$PYTHONPATH:$(pwd)/scripts/recon:$(pwd)/scripts/recon/tests/python
for test_script in $(find tests/python -name "*.py"); do
    echo "Running $test_script"
    python "$test_script"
done

echo "All tests finished."

echo "Running gitleaks to check for secrets..."
gitleaks detect --source="." -v

