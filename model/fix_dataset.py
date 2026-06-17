import pandas as pd

df = pd.read_csv('data/dataset.csv')

indian_legit = [
    'https://letsupgrade.in', 'https://internshala.com',
    'https://nptel.ac.in', 'https://swayam.gov.in',
    'https://collegedunia.com', 'https://shiksha.com',
    'https://naukri.com', 'https://linkedin.com',
    'https://unstop.com', 'https://hackerrank.com',
    'https://leetcode.com', 'https://geeksforgeeks.org',
]

new_rows = []
for url in indian_legit:
    for _ in range(50):
        new_rows.append({'url': url, 'label': 0})

new_df = pd.DataFrame(new_rows)
df = pd.concat([df, new_df], ignore_index=True).sample(frac=1, random_state=42)
df.to_csv('data/dataset.csv', index=False)
print('Done! Total rows:', len(df))