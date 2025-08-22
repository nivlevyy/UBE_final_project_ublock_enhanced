import pandas as pd
import json

if __name__ == '__main__':
    new_data = pd.read_csv('flattened_urls.csv')
    mylist = list(new_data['URL'])

    with open('open_phish_data_new.json', 'w') as f:
        json.dump(mylist, f, indent=2)
