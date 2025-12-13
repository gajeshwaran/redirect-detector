import zipfile
import os

print('Extracting...')
with zipfile.ZipFile('gh_cli.zip', 'r') as zip_ref:
    zip_ref.extractall('gh_dist')
print('Extracted.')
