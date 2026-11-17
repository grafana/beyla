#!/usr/bin/env sh
export PIP_DISABLE_PIP_VERSION_CHECK=1

python -m venv .dep_tree_env
# shellcheck source=/dev/null # The virtualenv was generated immediately above.
. ".dep_tree_env/bin/activate"

pip install --root-user-action ignore -r requirements.txt
pip install --root-user-action ignore pipdeptree
pipdeptree --exclude pipdeptree >dependency-tree.txt
